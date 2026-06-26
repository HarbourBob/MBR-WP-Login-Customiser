<?php
/**
 * Two-factor authentication (TOTP, RFC 6238).
 *
 * Per-user, opt-in. Users enrol on their profile; at login a one-time code is
 * required as a second factor. Recovery codes, an admin reset on the user-edit
 * screen, and the MBR_LOGIN_2FA_DISABLE wp-config constant provide lock-out
 * recovery.
 *
 * The TOTP secret is encrypted at rest with a key derived from the site salts.
 * Recovery codes are hashed independently of the salts so they survive a salt
 * rotation (which would otherwise make every secret undecryptable).
 *
 * @package MBR_Login_Customiser
 */

if (!defined('ABSPATH')) {
    exit;
}

class MBR_Login_2FA {

    const SECRET_META    = 'mbr_2fa_secret';
    const PENDING_META   = 'mbr_2fa_pending';
    const RECOVERY_META  = 'mbr_2fa_recovery';

    /**
     * Register WordPress hooks for this module.
     */
    public function register_hooks() {
        // Verify the second factor last, after every other access gate.
        add_filter('authenticate', array($this, 'check_2fa'), 100, 3);
        add_action('login_form', array($this, 'render_login_field'));

        // Application Passwords policy for 2FA users (see check_2fa).
        add_action('application_password_did_authenticate', array($this, 'note_app_password_auth'));
        add_filter('wp_is_application_passwords_available_for_user', array($this, 'filter_app_passwords_available'), 10, 2);

        // Per-user enrolment on the profile screens.
        add_action('show_user_profile', array($this, 'render_profile_section'));
        add_action('edit_user_profile', array($this, 'render_profile_section'));
        add_action('personal_options_update', array($this, 'save_profile'));
        add_action('edit_user_profile_update', array($this, 'save_profile'));
    }

    /**
     * Set true by core when the current request authenticated with a valid
     * Application Password. Not forgeable by a client (a real app password must
     * have validated first), so it is a safe signal that this is non-interactive
     * API auth rather than the interactive login form.
     *
     * @var bool
     */
    private $via_app_password = false;

    public function note_app_password_auth() {
        $this->via_app_password = true;
    }

    /**
     * Application Passwords policy. In the default 'block' mode, users who have
     * 2FA enabled cannot create or use Application Passwords at all, so there is
     * no password-only path that skips the second factor. In 'allow' mode they
     * remain available and serve as the API credential.
     *
     * @param bool    $available
     * @param WP_User $user
     * @return bool
     */
    public function filter_app_passwords_available($available, $user) {
        if (!$available) {
            return $available;
        }
        if (get_option('mbr_custom_login_2fa_app_passwords', 'block') !== 'block') {
            return $available;
        }
        if (is_object($user) && !empty($user->ID) && $this->user_has_2fa($user->ID)) {
            return false;
        }
        return $available;
    }

    /* =====================================================================
     * Feature state
     * ================================================================== */

    public function feature_enabled() {
        if ((bool) get_option('mbr_custom_login_2fa_enabled', 0)) {
            return true;
        }
        // Network admins can require 2FA across all sites.
        return (bool) MBR_Login_Options::network_get('mbr_custom_login_network_2fa', 0);
    }

    /**
     * Emergency bypass: define('MBR_LOGIN_2FA_DISABLE', true) in wp-config.php.
     */
    private function emergency_disabled() {
        return defined('MBR_LOGIN_2FA_DISABLE') && MBR_LOGIN_2FA_DISABLE;
    }

    public function user_has_2fa($user_id) {
        return $this->get_secret($user_id) !== '';
    }

    /* =====================================================================
     * Login gate
     * ================================================================== */

    /**
     * authenticate filter (priority 100): require a valid second factor for
     * enrolled users. Runs only on a fully-authenticated WP_User, so it never
     * interferes with a password failure or an earlier access block.
     */
    public function check_2fa($user, $username, $password) {
        if (!($user instanceof WP_User) || empty($user->ID)) {
            return $user;
        }
        if (!$this->feature_enabled() || $this->emergency_disabled()) {
            return $user;
        }
        if (!$this->user_has_2fa($user->ID)) {
            return $user;
        }

        // Non-interactive API auth via a valid Application Password is its own
        // credential; the interactive code cannot be supplied here. In 'block'
        // mode 2FA users have no app passwords, so this never fires for them.
        if ($this->via_app_password) {
            return $user;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- this rides the core login POST.
        $code = isset($_POST['mbr_2fa_code']) ? sanitize_text_field(wp_unslash($_POST['mbr_2fa_code'])) : '';

        if ($code === '') {
            return new WP_Error(
                'mbr_2fa_required',
                __('<strong>Authentication code required.</strong> Enter the code from your authenticator app.', 'mbr-login-customiser')
            );
        }
        if ($this->verify_code($user->ID, $code)) {
            return $user;
        }
        return new WP_Error(
            'mbr_2fa_invalid',
            __('<strong>Invalid authentication code.</strong> Please try again.', 'mbr-login-customiser')
        );
    }

    /**
     * Render the optional code field on the login form.
     */
    public function render_login_field() {
        if (!$this->feature_enabled()) {
            return;
        }
        ?>
        <p>
            <label for="mbr_2fa_code"><?php esc_html_e('Authentication code', 'mbr-login-customiser'); ?>
                <input type="text" name="mbr_2fa_code" id="mbr_2fa_code" class="input"
                       autocomplete="one-time-code" inputmode="numeric"
                       value="" size="20" />
            </label>
            <span class="description"><?php esc_html_e('Only needed if you have two-factor authentication enabled.', 'mbr-login-customiser'); ?></span>
        </p>
        <?php
    }

    /**
     * Verify a submitted code against the user's TOTP secret, then recovery
     * codes (single-use).
     */
    public function verify_code($user_id, $code) {
        $code   = trim((string) $code);
        $secret = $this->get_secret($user_id);
        if ($secret !== '' && $this->verify_totp($secret, $code)) {
            return true;
        }
        return $this->consume_recovery_code($user_id, $code);
    }

    /* =====================================================================
     * TOTP (RFC 4226 / 6238)
     * ================================================================== */

    /**
     * The 6-digit HOTP value for a secret and counter (public for testing).
     */
    public function hotp_code($secret_b32, $counter) {
        $value = $this->hotp($this->base32_decode($secret_b32), (int) $counter);
        return str_pad((string) $value, 6, '0', STR_PAD_LEFT);
    }

    /**
     * Verify a TOTP code, allowing one step of clock drift either way.
     */
    public function verify_totp($secret_b32, $code, $timestamp = null) {
        $code = preg_replace('/\D/', '', (string) $code);
        if (strlen($code) !== 6) {
            return false;
        }
        $timestamp = (null === $timestamp) ? time() : (int) $timestamp;
        $step = (int) floor($timestamp / 30);
        for ($w = -1; $w <= 1; $w++) {
            $calc = $this->hotp_code($secret_b32, $step + $w);
            if (hash_equals($calc, $code)) {
                return true;
            }
        }
        return false;
    }

    private function hotp($secret_bytes, $counter) {
        $binctr = pack('N*', 0) . pack('N*', $counter); // 8-byte big-endian counter
        $hash   = hash_hmac('sha1', $binctr, $secret_bytes, true);
        $offset = ord($hash[19]) & 0x0f;
        $part   = ((ord($hash[$offset]) & 0x7f) << 24)
                | ((ord($hash[$offset + 1]) & 0xff) << 16)
                | ((ord($hash[$offset + 2]) & 0xff) << 8)
                | (ord($hash[$offset + 3]) & 0xff);
        return $part % 1000000;
    }

    public function generate_secret() {
        return $this->base32_encode(random_bytes(20));
    }

    /**
     * Build the otpauth:// URI for an authenticator app.
     */
    public function otpauth_uri($secret_b32, $account) {
        $issuer = wp_specialchars_decode((string) get_bloginfo('name'), ENT_QUOTES);
        if ($issuer === '') {
            $issuer = 'WordPress';
        }
        $label = rawurlencode($issuer) . ':' . rawurlencode($account);
        return 'otpauth://totp/' . $label
            . '?secret=' . rawurlencode($secret_b32)
            . '&issuer=' . rawurlencode($issuer)
            . '&algorithm=SHA1&digits=6&period=30';
    }

    private function base32_decode($b32) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $b32 = strtoupper((string) $b32);
        $buffer = 0; $bits = 0; $out = '';
        $len = strlen($b32);
        for ($i = 0; $i < $len; $i++) {
            $v = strpos($alphabet, $b32[$i]);
            if (false === $v) {
                continue; // skip padding / separators
            }
            $buffer = ($buffer << 5) | $v;
            $bits += 5;
            if ($bits >= 8) {
                $bits -= 8;
                $out .= chr(($buffer >> $bits) & 0xFF);
            }
        }
        return $out;
    }

    private function base32_encode($data) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $out = ''; $buffer = 0; $bits = 0;
        $len = strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $buffer = ($buffer << 8) | ord($data[$i]);
            $bits += 8;
            while ($bits >= 5) {
                $bits -= 5;
                $out .= $alphabet[($buffer >> $bits) & 0x1F];
            }
        }
        if ($bits > 0) {
            $out .= $alphabet[($buffer << (5 - $bits)) & 0x1F];
        }
        return $out;
    }

    /* =====================================================================
     * Recovery codes
     * ================================================================== */

    public function generate_recovery_codes($count = 10) {
        $codes = array();
        for ($i = 0; $i < $count; $i++) {
            $codes[] = strtolower(wp_generate_password(10, false, false));
        }
        return $codes;
    }

    private function hash_recovery($code) {
        return hash('sha256', strtolower(trim((string) $code)));
    }

    public function store_recovery_codes($user_id, array $plain_codes) {
        $hashes = array_map(array($this, 'hash_recovery'), $plain_codes);
        update_user_meta($user_id, self::RECOVERY_META, $hashes);
    }

    public function recovery_codes_remaining($user_id) {
        $hashes = get_user_meta($user_id, self::RECOVERY_META, true);
        return is_array($hashes) ? count($hashes) : 0;
    }

    private function consume_recovery_code($user_id, $code) {
        $hashes = get_user_meta($user_id, self::RECOVERY_META, true);
        if (!is_array($hashes) || empty($hashes)) {
            return false;
        }
        $target = $this->hash_recovery($code);
        foreach ($hashes as $i => $stored) {
            if (hash_equals((string) $stored, $target)) {
                unset($hashes[$i]);
                update_user_meta($user_id, self::RECOVERY_META, array_values($hashes));
                return true;
            }
        }
        return false;
    }

    /* =====================================================================
     * Secret storage (encrypted at rest)
     * ================================================================== */

    public function get_secret($user_id) {
        $stored = get_user_meta($user_id, self::SECRET_META, true);
        return $stored ? $this->decrypt((string) $stored) : '';
    }

    private function get_pending($user_id) {
        $stored = get_user_meta($user_id, self::PENDING_META, true);
        return $stored ? $this->decrypt((string) $stored) : '';
    }

    private function set_pending($user_id, $secret_b32) {
        update_user_meta($user_id, self::PENDING_META, $this->encrypt($secret_b32));
    }

    private function set_secret($user_id, $secret_b32) {
        update_user_meta($user_id, self::SECRET_META, $this->encrypt($secret_b32));
    }

    public function disable_for_user($user_id) {
        delete_user_meta($user_id, self::SECRET_META);
        delete_user_meta($user_id, self::PENDING_META);
        delete_user_meta($user_id, self::RECOVERY_META);
    }

    private function enc_key() {
        return hash('sha256', wp_salt('auth'), true);
    }

    private function gcm_available() {
        return function_exists('openssl_encrypt')
            && in_array('aes-256-gcm', openssl_get_cipher_methods(), true);
    }

    private function encrypt($plain) {
        // Preferred: authenticated encryption (AES-256-GCM). The tag detects any
        // tampering with the stored ciphertext.
        if ($this->gcm_available()) {
            $iv  = random_bytes(12);
            $tag = '';
            $ct  = openssl_encrypt($plain, 'aes-256-gcm', $this->enc_key(), OPENSSL_RAW_DATA, $iv, $tag);
            if (false !== $ct) {
                return 'g:' . base64_encode($iv . $tag . $ct);
            }
        }
        // Fallback: CBC (older OpenSSL without GCM).
        if (function_exists('openssl_encrypt')) {
            $iv = random_bytes(16);
            $ct = openssl_encrypt($plain, 'aes-256-cbc', $this->enc_key(), OPENSSL_RAW_DATA, $iv);
            if (false !== $ct) {
                return 'e:' . base64_encode($iv . $ct);
            }
        }
        // Last resort: no OpenSSL at all.
        return 'p:' . base64_encode($plain);
    }

    private function decrypt($stored) {
        $stored = (string) $stored;

        if (strpos($stored, 'g:') === 0 && $this->gcm_available()) {
            $raw = base64_decode(substr($stored, 2));
            if ($raw === false || strlen($raw) <= 28) {
                return '';
            }
            $iv  = substr($raw, 0, 12);
            $tag = substr($raw, 12, 16);
            $ct  = substr($raw, 28);
            $pt  = openssl_decrypt($ct, 'aes-256-gcm', $this->enc_key(), OPENSSL_RAW_DATA, $iv, $tag);
            return $pt === false ? '' : $pt;
        }

        // Legacy CBC secrets stored before the GCM upgrade.
        if (strpos($stored, 'e:') === 0 && function_exists('openssl_decrypt')) {
            $raw = base64_decode(substr($stored, 2));
            if ($raw === false || strlen($raw) <= 16) {
                return '';
            }
            $iv = substr($raw, 0, 16);
            $ct = substr($raw, 16);
            $pt = openssl_decrypt($ct, 'aes-256-cbc', $this->enc_key(), OPENSSL_RAW_DATA, $iv);
            return $pt === false ? '' : $pt;
        }

        if (strpos($stored, 'p:') === 0) {
            return (string) base64_decode(substr($stored, 2));
        }

        return '';
    }

    /* =====================================================================
     * Profile enrolment
     * ================================================================== */

    /**
     * Render the 2FA section on a user profile screen.
     */
    public function render_profile_section($user) {
        if (!$this->feature_enabled()) {
            return;
        }
        if (!is_object($user) || empty($user->ID)) {
            return;
        }
        $is_own  = (get_current_user_id() === (int) $user->ID);
        $has     = $this->user_has_2fa($user->ID);

        echo '<h2>' . esc_html__('Two-Factor Authentication', 'mbr-login-customiser') . '</h2>';
        echo '<table class="form-table" role="presentation"><tbody>';

        // One-time messages.
        $codes = get_transient('mbr_2fa_codes_' . $user->ID);
        if ($codes && is_array($codes)) {
            delete_transient('mbr_2fa_codes_' . $user->ID);
            echo '<tr><th>' . esc_html__('Recovery codes', 'mbr-login-customiser') . '</th><td>';
            echo '<p class="description">' . esc_html__('Save these now. Each can be used once if you lose your device. They will not be shown again.', 'mbr-login-customiser') . '</p>';
            echo '<p style="font-family:monospace;line-height:1.8;">';
            foreach ($codes as $c) {
                echo esc_html($c) . '<br>';
            }
            echo '</p></td></tr>';
        }
        $err = get_transient('mbr_2fa_error_' . $user->ID);
        if ($err) {
            delete_transient('mbr_2fa_error_' . $user->ID);
            echo '<tr><th></th><td><p style="color:#b32d2e;">' . esc_html($err) . '</p></td></tr>';
        }

        if ($has) {
            echo '<tr><th>' . esc_html__('Status', 'mbr-login-customiser') . '</th><td>';
            echo '<strong style="color:#1a7f37;">' . esc_html__('Enabled', 'mbr-login-customiser') . '</strong> &nbsp; ';
            printf(
                /* translators: %d: number of unused recovery codes remaining */
                esc_html__('(%d recovery codes remaining)', 'mbr-login-customiser'),
                (int) $this->recovery_codes_remaining($user->ID)
            );
            echo '</td></tr>';

            if ($is_own) {
                echo '<tr><th>' . esc_html__('Recovery codes', 'mbr-login-customiser') . '</th><td><label>';
                echo '<input type="checkbox" name="mbr_2fa_regen" value="1"> ' . esc_html__('Generate a new set of recovery codes', 'mbr-login-customiser');
                echo '</label></td></tr>';
                echo '<tr><th>' . esc_html__('Disable', 'mbr-login-customiser') . '</th><td><label>';
                echo '<input type="checkbox" name="mbr_2fa_disable" value="1"> ' . esc_html__('Turn off two-factor authentication', 'mbr-login-customiser');
                echo '</label></td></tr>';
            } else {
                // Admin editing another user: rescue option.
                echo '<tr><th>' . esc_html__('Reset', 'mbr-login-customiser') . '</th><td><label>';
                echo '<input type="checkbox" name="mbr_2fa_admin_reset" value="1"> ' . esc_html__('Disable two-factor authentication for this user', 'mbr-login-customiser');
                echo '</label></td></tr>';
            }
        } elseif ($is_own) {
            // Enrolment: ensure a pending secret exists for this round-trip.
            $pending = $this->get_pending($user->ID);
            if ('' === $pending) {
                $pending = $this->generate_secret();
                $this->set_pending($user->ID, $pending);
            }
            $uri = $this->otpauth_uri($pending, $user->user_login);

            echo '<tr><th>' . esc_html__('Scan this code', 'mbr-login-customiser') . '</th><td>';
            if (class_exists('MBR_QR')) {
                $svg = MBR_QR::to_svg($uri, 5, 4);
                if ($svg !== '') {
                    echo '<div style="background:#fff;display:inline-block;padding:8px;border:1px solid #dcdcde;">' . $svg . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- generated SVG markup
                }
            }
            echo '<p class="description">' . esc_html__('Scan with your authenticator app (Google Authenticator, Authy, 1Password…), or enter the key below manually.', 'mbr-login-customiser') . '</p>';
            echo '</td></tr>';

            echo '<tr><th>' . esc_html__('Setup key', 'mbr-login-customiser') . '</th><td>';
            echo '<code style="font-size:14px;letter-spacing:2px;">' . esc_html(trim(chunk_split($pending, 4, ' '))) . '</code>';
            echo '<p class="description">' . esc_html__('Manual entry: add this key to your authenticator app, then enter the 6-digit code it shows below and save your profile.', 'mbr-login-customiser') . '</p>';
            echo '</td></tr>';
            echo '<tr><th>' . esc_html__('Verification code', 'mbr-login-customiser') . '</th><td>';
            echo '<input type="text" name="mbr_2fa_verify" value="" class="regular-text" inputmode="numeric" autocomplete="off">';
            echo '<p class="description">' . esc_html__('Enter the current code to enable two-factor authentication.', 'mbr-login-customiser') . '</p>';
            echo '</td></tr>';
        } else {
            echo '<tr><th>' . esc_html__('Status', 'mbr-login-customiser') . '</th><td>' . esc_html__('Not enabled.', 'mbr-login-customiser') . '</td></tr>';
        }

        echo '</tbody></table>';
    }

    /**
     * Handle profile save for the 2FA fields.
     */
    public function save_profile($user_id) {
        if (!$this->feature_enabled()) {
            return;
        }
        if (!current_user_can('edit_user', $user_id)) {
            return;
        }

        $is_own = (get_current_user_id() === (int) $user_id);

        // Admin resetting another user's 2FA.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- rides the core profile-update nonce.
        if (!$is_own && !empty($_POST['mbr_2fa_admin_reset'])) {
            $this->disable_for_user($user_id);
            return;
        }

        if (!$is_own) {
            return;
        }

        // Own profile: disable.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if (!empty($_POST['mbr_2fa_disable'])) {
            $this->disable_for_user($user_id);
            return;
        }

        // Own profile: regenerate recovery codes.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if (!empty($_POST['mbr_2fa_regen']) && $this->user_has_2fa($user_id)) {
            $codes = $this->generate_recovery_codes();
            $this->store_recovery_codes($user_id, $codes);
            set_transient('mbr_2fa_codes_' . $user_id, $codes, 300);
            return;
        }

        // Own profile: activate from a pending secret after verifying a code.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $verify  = isset($_POST['mbr_2fa_verify']) ? sanitize_text_field(wp_unslash($_POST['mbr_2fa_verify'])) : '';
        $pending = $this->get_pending($user_id);
        if ($verify !== '' && $pending !== '') {
            if ($this->verify_totp($pending, $verify)) {
                $this->set_secret($user_id, $pending);
                delete_user_meta($user_id, self::PENDING_META);
                $codes = $this->generate_recovery_codes();
                $this->store_recovery_codes($user_id, $codes);
                set_transient('mbr_2fa_codes_' . $user_id, $codes, 300);
            } else {
                set_transient('mbr_2fa_error_' . $user_id, __('That code was not correct. Two-factor authentication was not enabled. Please try again.', 'mbr-login-customiser'), 60);
            }
        }
    }

    /**
     * Count users with 2FA enabled (for the admin tab).
     */
    public function count_enrolled_users() {
        $users = get_users(array(
            'meta_key'     => self::SECRET_META,
            'meta_compare' => 'EXISTS',
            'fields'       => 'ID',
            'number'       => 1000,
        ));
        return count($users);
    }
}
