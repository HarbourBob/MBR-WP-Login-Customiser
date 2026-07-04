<?php
/**
 * Trusted devices.
 *
 * Lets a user tick "trust this device" when they complete a second factor, so
 * that on the same browser they aren't prompted for the second factor again
 * until the trust expires (30 days by default). Reduces 2FA friction — the main
 * reason people turn it off.
 *
 * Mechanics: a signed cookie is set on the browser and a matching device record
 * is stored in user meta. Both must line up for the device to be trusted, which
 * means a device can be revoked server-side from the user's profile. The cookie
 * is HMAC-signed with a stored secret so it can't be forged, bound to the user
 * ID, and given a hard expiry.
 *
 * Security note: a trusted device only skips the SECOND factor — the password
 * (or passkey) is still required. Trust is per-browser, time-limited, and
 * revocable. Treat a trusted-device cookie like any other login cookie.
 *
 * The 2FA and passkey second-factor gates ask this module, via the
 * 'mbr_login_trusted_device' filter, whether to skip the prompt — so the
 * modules stay decoupled.
 *
 * @package MBR_Login_Customiser
 */

if (!defined('ABSPATH')) {
    exit;
}

class MBR_Login_Trusted_Devices {

    /** User meta: map of device_id => record. */
    const DEVICES_META = 'mbr_trusted_devices';

    public function register_hooks() {
        // The gate consulted by the 2FA / passkey second-factor checks.
        add_filter('mbr_login_trusted_device', array($this, 'filter_is_trusted'), 10, 2);

        // "Trust this device" checkbox on the login form.
        add_action('login_form', array($this, 'render_checkbox'));

        // Capture the "trust" intent the moment it is submitted on ANY login
        // attempt (even a failed 2FA step), so it survives a multi-step or
        // redirect-based login and is still known when wp_login finally fires.
        add_filter('authenticate', array($this, 'capture_trust_intent'), 1, 3);

        // Set the cookie after a successful login when the box was ticked.
        add_action('wp_login', array($this, 'maybe_remember_device'), 5, 2);

        // NB: trust deliberately survives logout — a trusted device stays trusted
        // until it expires or is revoked from the profile. We do NOT clear it on
        // logout, or "remember this device" would be pointless.

        // Profile management (list + revoke).
        add_action('show_user_profile', array($this, 'render_profile_section'));
        add_action('edit_user_profile', array($this, 'render_profile_section'));
        add_action('personal_options_update', array($this, 'save_profile'));
        add_action('edit_user_profile_update', array($this, 'save_profile'));
    }

    /* =====================================================================
     * Configuration
     * ================================================================== */

    public function enabled() {
        return (bool) get_option('mbr_custom_login_trusted_enabled', 0);
    }

    private function trust_days() {
        return max(1, (int) get_option('mbr_custom_login_trusted_days', 30));
    }

    /** A stable, plugin-owned signing secret (survives salt rotation). */
    private function secret() {
        $secret = get_option('mbr_custom_login_trusted_secret', '');
        if (!$secret) {
            $secret = bin2hex(random_bytes(32));
            update_option('mbr_custom_login_trusted_secret', $secret, false);
        }
        return $secret;
    }

    private function cookie_name() {
        return 'mbr_td_' . (defined('COOKIEHASH') ? COOKIEHASH : md5(home_url()));
    }

    /* =====================================================================
     * Trust check
     * ================================================================== */

    /**
     * Filter callback for 'mbr_login_trusted_device'.
     *
     * @param bool $default
     * @param int  $user_id
     * @return bool
     */
    public function filter_is_trusted($default, $user_id) {
        if (!$this->enabled()) {
            return $default;
        }
        return $this->is_trusted((int) $user_id) ? true : $default;
    }

    /**
     * Is the current browser a trusted device for this user?
     */
    public function is_trusted($user_id) {
        if (empty($_COOKIE[$this->cookie_name()])) {
            $this->debug('is_trusted: no trust cookie present for this browser');
            return false;
        }
        $raw   = sanitize_text_field(wp_unslash($_COOKIE[$this->cookie_name()]));
        $parts = explode('|', $raw, 4);
        if (count($parts) !== 4) {
            $this->debug('is_trusted: malformed cookie');
            return false;
        }
        list($uid, $device_id, $expires, $mac) = $parts;

        if ((int) $uid !== (int) $user_id) {
            $this->debug('is_trusted: cookie user ' . $uid . ' != login user ' . $user_id);
            return false;
        }
        if (!ctype_alnum($device_id) || (int) $expires < time()) {
            $this->debug('is_trusted: bad device id or expired cookie');
            return false;
        }
        // Verify the signature.
        $expected = $this->sign($uid . '|' . $device_id . '|' . $expires);
        if (!hash_equals($expected, (string) $mac)) {
            $this->debug('is_trusted: signature mismatch');
            return false;
        }
        // Confirm the device is still recorded (i.e. not revoked) and unexpired.
        $devices = $this->get_devices($user_id);
        if (!isset($devices[$device_id])) {
            $this->debug('is_trusted: device not in stored list (revoked or missing)');
            return false;
        }
        if ((int) $devices[$device_id]['expires'] < time()) {
            $this->debug('is_trusted: stored device expired');
            return false;
        }
        $this->debug('is_trusted: TRUSTED — skipping second factor for user ' . $user_id);
        return true;
    }

    /* =====================================================================
     * Login form + cookie issuance
     * ================================================================== */

    public function render_checkbox() {
        if (!$this->enabled()) {
            return;
        }
        $this->debug('render_checkbox: outputting trust checkbox on login_form');
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- read-only, keeps the tick across a re-rendered login form.
        $checked = !empty($_POST['mbr_trust_device']);
        ?>
        <p style="margin-bottom:12px;">
            <label>
                <input type="checkbox" name="mbr_trust_device" value="1" <?php checked($checked); ?>>
                <?php
                printf(
                    /* translators: %d: number of days */
                    esc_html__('Trust this device for %d days (skip the second step here)', 'mbr-login-customiser'),
                    (int) $this->trust_days()
                );
                ?>
            </label>
        </p>
        <?php
    }

    /**
     * Runs early on every login attempt. If the trust box was submitted, stash a
     * short-lived intent cookie so the choice survives a multi-step 2FA login
     * (where the completing request may not carry the checkbox). Returns $user
     * untouched — this only observes.
     */
    public function capture_trust_intent($user, $username = '', $password = '') {
        if (!$this->enabled()) {
            return $user;
        }
        // Diagnostic: which of our fields actually arrived with this login POST.
        if (defined('WP_DEBUG') && WP_DEBUG && !empty($_POST)) {
            $mbr_keys = preg_grep('/^mbr_/', array_keys($_POST)); // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $this->debug('authenticate: mbr_* POST fields present = [' . implode(', ', $mbr_keys) . ']');
        }
        if (!empty($_POST['mbr_trust_device']) && !headers_sent()) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- rides the login POST.
            setcookie($this->intent_cookie_name(), '1', array(
                'expires'  => time() + 600,
                'path'     => defined('COOKIEPATH') ? COOKIEPATH : '/',
                'domain'   => defined('COOKIE_DOMAIN') ? COOKIE_DOMAIN : '',
                'secure'   => is_ssl(),
                'httponly' => true,
                'samesite' => 'Lax',
            ));
            $_COOKIE[$this->intent_cookie_name()] = '1';
            $this->debug('authenticate: trust intent captured (cookie set)');
        }
        return $user;
    }

    /**
     * On successful login, if the box was ticked (now or on an earlier step of
     * this login), record this device and set the signed cookie. We deliberately
     * do NOT require the user to already have a second factor: recording a device
     * for a user with none is harmless (the cookie is simply never consulted for
     * them), and removing that cross-module check removes a way for recording to
     * silently fail.
     *
     * @param string  $user_login
     * @param WP_User $user
     */
    public function maybe_remember_device($user_login, $user = null) {
        if (!$this->enabled()) {
            $this->debug('skip: feature disabled');
            return;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- rides the core login POST.
        $wants = !empty($_POST['mbr_trust_device']) || !empty($_COOKIE[$this->intent_cookie_name()]);
        if (!$wants) {
            $this->debug('skip: no trust intent (neither POST field nor intent cookie present)');
            return;
        }
        if (!($user instanceof WP_User) || empty($user->ID)) {
            $this->debug('skip: no WP_User passed to wp_login');
            return;
        }

        $device_id = $this->new_device_id();
        $expires   = time() + ($this->trust_days() * DAY_IN_SECONDS);

        // Store the device record.
        $devices = $this->prune($this->get_devices($user->ID));
        $devices[$device_id] = array(
            'created' => time(),
            'expires' => $expires,
            'ua'      => isset($_SERVER['HTTP_USER_AGENT']) ? substr(sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])), 0, 200) : '',
            'ip_hash' => hash_hmac('sha256', MBR_Login_Security::get_client_ip(), wp_salt('auth')),
        );
        update_user_meta($user->ID, self::DEVICES_META, $devices);

        // Set the signed trust cookie and clear the one-time intent cookie.
        $payload = $user->ID . '|' . $device_id . '|' . $expires;
        $value   = $payload . '|' . $this->sign($payload);
        $this->set_cookie($value, $expires);
        $this->clear_intent_cookie();
        $this->debug('recorded device ' . $device_id . ' for user ' . $user->ID);
    }

    private function intent_cookie_name() {
        return 'mbr_tdi_' . (defined('COOKIEHASH') ? COOKIEHASH : md5(home_url()));
    }

    private function clear_intent_cookie() {
        unset($_COOKIE[$this->intent_cookie_name()]);
        if (headers_sent()) {
            return;
        }
        setcookie($this->intent_cookie_name(), ' ', array(
            'expires'  => time() - YEAR_IN_SECONDS,
            'path'     => defined('COOKIEPATH') ? COOKIEPATH : '/',
            'domain'   => defined('COOKIE_DOMAIN') ? COOKIE_DOMAIN : '',
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ));
    }

    /** Write a diagnostic line only when WP_DEBUG is on. Silent in production. */
    private function debug($msg) {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('[MBR Trusted Devices] ' . $msg);
        }
    }

    /* =====================================================================
     * Cookie helpers
     * ================================================================== */

    private function sign($payload) {
        return hash_hmac('sha256', $payload, $this->secret());
    }

    private function new_device_id() {
        return bin2hex(random_bytes(16)); // alphanumeric (hex) -> passes ctype_alnum
    }

    private function set_cookie($value, $expires) {
        $params = array(
            'expires'  => $expires,
            'path'     => defined('COOKIEPATH') ? COOKIEPATH : '/',
            'domain'   => defined('COOKIE_DOMAIN') ? COOKIE_DOMAIN : '',
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        );
        // Not output buffering-safe if headers already sent; guard quietly.
        if (!headers_sent()) {
            setcookie($this->cookie_name(), $value, $params);
            $_COOKIE[$this->cookie_name()] = $value;
            $this->debug('set_cookie: trust cookie written (expires ' . gmdate('Y-m-d', $expires) . ')');
        } else {
            $file = ''; $line = 0; headers_sent($file, $line);
            $this->debug('set_cookie: BLOCKED — headers already sent by ' . $file . ':' . $line . ' (cookie NOT written)');
        }
    }

    public function clear_cookie() {
        // Retained for backward compatibility / manual use. Trust is NOT cleared
        // on logout by design; revocation happens from the profile or on expiry.
        if (headers_sent()) {
            return;
        }
        setcookie($this->cookie_name(), ' ', array(
            'expires'  => time() - YEAR_IN_SECONDS,
            'path'     => defined('COOKIEPATH') ? COOKIEPATH : '/',
            'domain'   => defined('COOKIE_DOMAIN') ? COOKIE_DOMAIN : '',
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ));
        unset($_COOKIE[$this->cookie_name()]);
    }

    /* =====================================================================
     * Device storage
     * ================================================================== */

    public function get_devices($user_id) {
        $devices = get_user_meta($user_id, self::DEVICES_META, true);
        return is_array($devices) ? $devices : array();
    }

    /** Drop expired records; keep the newest 20. */
    private function prune($devices) {
        $now = time();
        foreach ($devices as $id => $rec) {
            if (!isset($rec['expires']) || (int) $rec['expires'] < $now) {
                unset($devices[$id]);
            }
        }
        if (count($devices) > 20) {
            uasort($devices, function ($a, $b) {
                return (int) ($b['created'] ?? 0) <=> (int) ($a['created'] ?? 0);
            });
            $devices = array_slice($devices, 0, 20, true);
        }
        return $devices;
    }

    public function revoke($user_id, $device_id) {
        $devices = $this->get_devices($user_id);
        if (isset($devices[$device_id])) {
            unset($devices[$device_id]);
            update_user_meta($user_id, self::DEVICES_META, $devices);
        }
    }

    public function revoke_all($user_id) {
        delete_user_meta($user_id, self::DEVICES_META);
    }

    /* =====================================================================
     * Profile management
     * ================================================================== */

    public function render_profile_section($user) {
        if (!$this->enabled() || !is_object($user) || empty($user->ID)) {
            return;
        }
        $devices = $this->prune($this->get_devices($user->ID));

        echo '<h2>' . esc_html__('Trusted devices', 'mbr-login-customiser') . '</h2>';
        echo '<table class="form-table" role="presentation"><tbody>';
        echo '<tr><th>' . esc_html__('Devices skipping the second step', 'mbr-login-customiser') . '</th><td>';

        if (empty($devices)) {
            echo '<p class="description">' . esc_html__('None. A device is added when someone ticks “Trust this device” at login.', 'mbr-login-customiser') . '</p>';
        } else {
            echo '<ul style="margin:0;">';
            foreach ($devices as $id => $rec) {
                $added   = !empty($rec['created']) ? date_i18n(get_option('date_format'), (int) $rec['created']) : '';
                $expires = !empty($rec['expires']) ? date_i18n(get_option('date_format'), (int) $rec['expires']) : '';
                $ua      = !empty($rec['ua']) ? $rec['ua'] : __('Unknown device', 'mbr-login-customiser');
                echo '<li style="margin-bottom:8px;">';
                echo '<label><input type="checkbox" name="mbr_trusted_revoke[]" value="' . esc_attr($id) . '"> ';
                echo '<strong>' . esc_html($this->friendly_ua($ua)) . '</strong> ';
                echo '<span class="description">';
                if ($added) {
                    echo esc_html(sprintf(/* translators: %s: date */ __('added %s', 'mbr-login-customiser'), $added));
                }
                if ($expires) {
                    echo ' &middot; ' . esc_html(sprintf(/* translators: %s: date */ __('expires %s', 'mbr-login-customiser'), $expires));
                }
                echo '</span></label>';
                echo '</li>';
            }
            echo '</ul>';
            echo '<p class="description">' . esc_html__('Tick a device and save your profile to revoke it. A revoked device is prompted for the second step again.', 'mbr-login-customiser') . '</p>';
            echo '<p><label><input type="checkbox" name="mbr_trusted_revoke_all" value="1"> ' . esc_html__('Revoke all trusted devices', 'mbr-login-customiser') . '</label></p>';
        }

        echo '</td></tr></tbody></table>';
    }

    public function save_profile($user_id) {
        if (!$this->enabled() || !current_user_can('edit_user', $user_id)) {
            return;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- rides the core profile-update nonce.
        if (!empty($_POST['mbr_trusted_revoke_all'])) {
            $this->revoke_all($user_id);
            return;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if (!empty($_POST['mbr_trusted_revoke']) && is_array($_POST['mbr_trusted_revoke'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $ids = array_map('sanitize_text_field', wp_unslash($_POST['mbr_trusted_revoke']));
            foreach ($ids as $id) {
                $this->revoke($user_id, $id);
            }
        }
    }

    /** Turn a raw UA string into something short and human. */
    private function friendly_ua($ua) {
        $ua = (string) $ua;
        $browser = __('Browser', 'mbr-login-customiser');
        if (stripos($ua, 'Edg') !== false)        { $browser = 'Edge'; }
        elseif (stripos($ua, 'Chrome') !== false) { $browser = 'Chrome'; }
        elseif (stripos($ua, 'Firefox') !== false){ $browser = 'Firefox'; }
        elseif (stripos($ua, 'Safari') !== false) { $browser = 'Safari'; }

        $os = '';
        if (stripos($ua, 'Windows') !== false)      { $os = 'Windows'; }
        elseif (stripos($ua, 'Mac OS') !== false)   { $os = 'macOS'; }
        elseif (stripos($ua, 'Android') !== false)  { $os = 'Android'; }
        elseif (stripos($ua, 'iPhone') !== false || stripos($ua, 'iPad') !== false) { $os = 'iOS'; }
        elseif (stripos($ua, 'Linux') !== false)    { $os = 'Linux'; }

        return trim($browser . ($os ? ' — ' . $os : ''));
    }

    /* =====================================================================
     * Settings tab
     * ================================================================== */

    public function render_settings_tab() {
        $enabled = (bool) get_option('mbr_custom_login_trusted_enabled', 0);
        $days    = (int) get_option('mbr_custom_login_trusted_days', 30);
        ?>
        <form method="post" action="options.php" style="margin-top:1em;">
            <?php settings_fields('mbr_custom_login_trusted'); ?>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><?php esc_html_e('Enable trusted devices', 'mbr-login-customiser'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="mbr_custom_login_trusted_enabled" value="1" <?php checked($enabled); ?>>
                            <?php esc_html_e('Let users skip the second factor on browsers they have trusted.', 'mbr-login-customiser'); ?>
                        </label>
                        <p class="description"><?php esc_html_e('A “Trust this device” checkbox appears at login when a second factor is active.', 'mbr-login-customiser'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="mbr_custom_login_trusted_days"><?php esc_html_e('Trust duration', 'mbr-login-customiser'); ?></label></th>
                    <td>
                        <input type="number" min="1" id="mbr_custom_login_trusted_days" name="mbr_custom_login_trusted_days" value="<?php echo esc_attr($days); ?>" style="width:80px;"> <?php esc_html_e('days', 'mbr-login-customiser'); ?>
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>

        <h2><?php esc_html_e('How it works', 'mbr-login-customiser'); ?></h2>
        <p class="description" style="max-width:680px;">
            <?php esc_html_e('When a user ticks “Trust this device” while signing in with a second factor, that browser is remembered with a signed cookie and skips the second step until the trust expires. Only the second factor is skipped — the password or passkey is always required.', 'mbr-login-customiser'); ?>
        </p>
        <p class="description" style="max-width:680px;">
            <?php
            printf(
                /* translators: %s: link to Users > Profile */
                esc_html__('Each user can review and revoke their trusted devices from %s.', 'mbr-login-customiser'),
                '<a href="' . esc_url(admin_url('profile.php')) . '">' . esc_html__('Users → Profile', 'mbr-login-customiser') . '</a>'
            );
            ?>
        </p>
        <?php
    }
}
