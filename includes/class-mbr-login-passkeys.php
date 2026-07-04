<?php
/**
 * Passkeys / WebAuthn (FIDO2) authentication.
 *
 * Per-user, opt-in. Users register a passkey on their profile; at login they can
 * sign in with it. Registration and assertion are verified entirely on the
 * server in pure PHP — CBOR is decoded here, the COSE public key is rebuilt into
 * a key OpenSSL/sodium understand, and the signature is checked with core
 * extensions. No Composer packages, no external services, no third-party calls.
 *
 * Two modes:
 *   - 'passwordless' (default): a "Sign in with a passkey" button is added
 *     ALONGSIDE the normal login form. The username/password path is left
 *     completely untouched, so the passkey is strictly a second door — it can
 *     never lock anyone out.
 *   - '2fa': the passkey is required as a second factor after a correct
 *     password for users who have registered one.
 *
 * Recovery: the wp-config constant MBR_LOGIN_PASSKEYS_DISABLE turns the whole
 * feature off, and an administrator can remove a user's passkeys from that
 * user's profile screen.
 *
 * Supported credential algorithms: ES256 (-7, the common one), RS256 (-257,
 * some platform authenticators) and EdDSA/Ed25519 (-8).
 *
 * @package MBR_Login_Customiser
 */

if (!defined('ABSPATH')) {
    exit;
}

class MBR_Login_Passkeys {

    /** User meta: array of registered credentials. */
    const CRED_META = 'mbr_passkey_credentials';

    /** User meta: this user's opaque WebAuthn user handle (base64url). */
    const HANDLE_META = 'mbr_passkey_handle';

    /** Transient prefix for a one-time, short-lived login challenge. */
    const LOGIN_CHAL_PREFIX = 'mbr_pk_lc_';

    /** Transient prefix for a one-time registration challenge (keyed per user). */
    const REG_CHAL_PREFIX = 'mbr_pk_rc_';

    /** How long a challenge is valid, in seconds. */
    const CHALLENGE_TTL = 120;

    /* =====================================================================
     * Hooks
     * ================================================================== */

    public function register_hooks() {
        // AJAX: registration ceremony (logged-in users only, nonce-protected).
        add_action('wp_ajax_mbr_passkey_register_options', array($this, 'ajax_register_options'));
        add_action('wp_ajax_mbr_passkey_register_verify', array($this, 'ajax_register_verify'));

        // AJAX: login ceremony (no logged-in user yet; security is the
        // cryptographic challenge-response, so no nonce is required).
        add_action('wp_ajax_nopriv_mbr_passkey_login_options', array($this, 'ajax_login_options'));
        add_action('wp_ajax_nopriv_mbr_passkey_login_verify', array($this, 'ajax_login_verify'));
        // Also allow an already-authenticated request to hit these harmlessly
        // (e.g. a stale login tab), so the endpoints resolve either way.
        add_action('wp_ajax_mbr_passkey_login_options', array($this, 'ajax_login_options'));
        add_action('wp_ajax_mbr_passkey_login_verify', array($this, 'ajax_login_verify'));

        // Login form: passwordless button + ceremony script.
        add_action('login_enqueue_scripts', array($this, 'enqueue_login_assets'));
        add_action('login_form', array($this, 'render_login_button'));

        // Second-factor gate (only used in '2fa' mode).
        add_filter('authenticate', array($this, 'check_second_factor'), 101, 3);

        // Profile enrolment.
        add_action('show_user_profile', array($this, 'render_profile_section'));
        add_action('edit_user_profile', array($this, 'render_profile_section'));
        add_action('personal_options_update', array($this, 'save_profile'));
        add_action('edit_user_profile_update', array($this, 'save_profile'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_profile_assets'));
    }

    /* =====================================================================
     * Feature state / configuration
     * ================================================================== */

    public function feature_enabled() {
        if ((bool) get_option('mbr_custom_login_passkeys_enabled', 0)) {
            return true;
        }
        return (bool) MBR_Login_Options::network_get('mbr_custom_login_network_passkeys', 0);
    }

    /** 'passwordless' (default) or '2fa'. */
    public function mode() {
        $mode = get_option('mbr_custom_login_passkeys_mode', 'passwordless');
        return in_array($mode, array('passwordless', '2fa'), true) ? $mode : 'passwordless';
    }

    private function emergency_disabled() {
        return defined('MBR_LOGIN_PASSKEYS_DISABLE') && MBR_LOGIN_PASSKEYS_DISABLE;
    }

    /**
     * Version string for passkeys.js. Uses the file's modification time so the
     * browser (and any server-side asset cache) always fetches the current file
     * after a deploy, rather than a stale cached copy under an unchanged version.
     */
    private function asset_version() {
        $path = MBR_CUSTOM_LOGIN_PLUGIN_DIR . 'passkeys.js';
        $mtime = @filemtime($path);
        return $mtime ? (string) $mtime : MBR_CUSTOM_LOGIN_VERSION;
    }

    public function user_has_passkey($user_id) {
        $creds = $this->get_credentials($user_id);
        return !empty($creds);
    }

    /**
     * The Relying Party ID: the site's registrable host, no scheme or port.
     * The browser requires this to be equal to, or a parent of, the origin host.
     */
    public function rp_id() {
        $host = wp_parse_url(home_url(), PHP_URL_HOST);
        return $host ? strtolower($host) : 'localhost';
    }

    public function rp_name() {
        $name = wp_specialchars_decode((string) get_bloginfo('name'), ENT_QUOTES);
        return $name !== '' ? $name : 'WordPress';
    }

    /** Expected origin, scheme + host + optional port, matching clientDataJSON. */
    public function expected_origin() {
        $parts  = wp_parse_url(home_url());
        $scheme = isset($parts['scheme']) ? $parts['scheme'] : 'https';
        $host   = isset($parts['host']) ? $parts['host'] : 'localhost';
        $origin = $scheme . '://' . $host;
        if (!empty($parts['port'])) {
            $origin .= ':' . $parts['port'];
        }
        return $origin;
    }

    /* =====================================================================
     * Second-factor gate (2fa mode only)
     *
     * In '2fa' mode the passkey is proven via the AJAX login ceremony, which
     * sets a short-lived, single-use "proof" transient tied to the user. This
     * gate then simply checks that proof exists on the password POST. Because
     * the passkey ceremony can't run inside the single password POST, the
     * front-end performs it first and submits the proof token in a hidden field.
     * ================================================================== */

    public function check_second_factor($user, $username, $password) {
        if (!($user instanceof WP_User) || empty($user->ID)) {
            return $user;
        }
        if (!$this->feature_enabled() || $this->emergency_disabled()) {
            return $user;
        }
        if ($this->mode() !== '2fa') {
            return $user;
        }
        if (!$this->user_has_passkey($user->ID)) {
            return $user;
        }

        // A trusted device (if that feature is on) skips the second factor.
        if (apply_filters('mbr_login_trusted_device', false, $user->ID)) {
            return $user;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- rides the core login POST.
        $proof = isset($_POST['mbr_passkey_proof']) ? sanitize_text_field(wp_unslash($_POST['mbr_passkey_proof'])) : '';
        if ($proof !== '' && $this->consume_second_factor_proof($user->ID, $proof)) {
            return $user;
        }

        return new WP_Error(
            'mbr_passkey_required',
            __('<strong>Passkey required.</strong> Use the “Sign in with a passkey” button to complete sign-in.', 'mbr-login-customiser')
        );
    }

    private function issue_second_factor_proof($user_id) {
        $token = bin2hex(random_bytes(16));
        // Stored in user meta (not a transient) so a persistent object cache
        // cannot drop it between the AJAX ceremony and the password POST.
        update_user_meta($user_id, 'mbr_passkey_sf_proof', $token . '|' . time());
        return $token;
    }

    private function consume_second_factor_proof($user_id, $token) {
        $token = preg_replace('/[^a-f0-9]/', '', (string) $token);
        if ($token === '') {
            return false;
        }
        $stored = get_user_meta($user_id, 'mbr_passkey_sf_proof', true);
        delete_user_meta($user_id, 'mbr_passkey_sf_proof'); // one-time
        if (!is_string($stored) || strpos($stored, '|') === false) {
            return false;
        }
        list($saved_token, $ts) = explode('|', $stored, 2);
        if ((time() - (int) $ts) > 120) {
            return false; // expired
        }
        return hash_equals($saved_token, $token);
    }

    /* ---------------------------------------------------------------------
     * Registration challenge storage.
     *
     * Stored in user meta rather than a transient. Transients on hosts with a
     * persistent object cache (e.g. Memcached) can silently drop values that
     * contain raw binary, and can be evicted between the two AJAX round-trips.
     * User meta is DB-backed and reliable — the same approach the 2FA module
     * uses for its pending secret. The value is base64url (ASCII) plus a
     * unix timestamp so we can enforce our own short expiry.
     * ------------------------------------------------------------------ */

    private function store_reg_challenge($user_id, $challenge_b64) {
        update_user_meta($user_id, 'mbr_passkey_reg_challenge', $challenge_b64 . '|' . time());
    }

    /** Return the pending challenge (base64url) once, then clear it. '' if none/expired. */
    private function take_reg_challenge($user_id) {
        $raw = get_user_meta($user_id, 'mbr_passkey_reg_challenge', true);
        delete_user_meta($user_id, 'mbr_passkey_reg_challenge'); // one-time
        if (!is_string($raw) || strpos($raw, '|') === false) {
            return '';
        }
        list($chal, $ts) = explode('|', $raw, 2);
        if ($chal === '' || (time() - (int) $ts) > self::CHALLENGE_TTL) {
            return '';
        }
        return $chal;
    }

    /* =====================================================================
     * Login button + assets
     * ================================================================== */

    public function enqueue_login_assets() {
        if (!$this->feature_enabled() || $this->emergency_disabled()) {
            return;
        }
        wp_enqueue_script(
            'mbr-passkeys',
            MBR_CUSTOM_LOGIN_PLUGIN_URL . 'passkeys.js',
            array(),
            $this->asset_version(),
            true
        );
        wp_localize_script('mbr-passkeys', 'mbrPasskeys', array(
            'ajaxUrl'    => admin_url('admin-ajax.php'),
            'mode'       => $this->mode(),
            'context'    => 'login',
            'redirectTo' => $this->safe_redirect_param(),
            'i18n'       => array(
                'unsupported' => __('This browser does not support passkeys.', 'mbr-login-customiser'),
                'failed'      => __('Passkey sign-in failed. Please try again or use your password.', 'mbr-login-customiser'),
                'cancelled'   => __('Passkey sign-in was cancelled.', 'mbr-login-customiser'),
                'working'     => __('Waiting for your passkey…', 'mbr-login-customiser'),
                'button'      => __('Sign in with a passkey', 'mbr-login-customiser'),
            ),
        ));
    }

    public function render_login_button() {
        if (!$this->feature_enabled() || $this->emergency_disabled()) {
            return;
        }
        ?>
        <div id="mbr-passkey-wrap" style="margin:12px 0;">
            <button type="button" id="mbr-passkey-login" class="button button-secondary" style="width:100%;box-sizing:border-box;display:none;">
                <?php esc_html_e('Sign in with a passkey', 'mbr-login-customiser'); ?>
            </button>
            <p id="mbr-passkey-status" style="margin:8px 0 0;text-align:center;" role="status" aria-live="polite"></p>
            <input type="hidden" name="mbr_passkey_proof" id="mbr-passkey-proof" value="">
        </div>
        <?php
    }

    /** A caller-supplied redirect_to, sanitised to a local URL. */
    private function safe_redirect_param() {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only, sanitised below.
        $raw = isset($_REQUEST['redirect_to']) ? wp_unslash($_REQUEST['redirect_to']) : '';
        $raw = is_string($raw) ? $raw : '';
        $url = wp_validate_redirect($raw, admin_url());
        return $url;
    }

    /* =====================================================================
     * AJAX: registration ceremony
     * ================================================================== */

    public function ajax_register_options() {
        check_ajax_referer('mbr_passkey_register', 'nonce');
        $user_id = get_current_user_id();
        if (!$user_id || !$this->feature_enabled()) {
            wp_send_json_error(array('message' => 'unavailable'), 400);
        }

        $challenge = $this->b64url_encode(random_bytes(32));
        $this->store_reg_challenge($user_id, $challenge);

        $user   = get_userdata($user_id);
        $handle = $this->get_or_create_handle($user_id);

        $exclude = array();
        foreach ($this->get_credentials($user_id) as $c) {
            $exclude[] = array('type' => 'public-key', 'id' => $c['id']); // id already base64url
        }

        wp_send_json_success(array(
            'challenge' => $challenge,
            'rp'        => array('id' => $this->rp_id(), 'name' => $this->rp_name()),
            'user'      => array(
                'id'          => $handle,
                'name'        => $user ? $user->user_login : ('user-' . $user_id),
                'displayName' => $user ? ($user->display_name ?: $user->user_login) : ('user-' . $user_id),
            ),
            'pubKeyCredParams' => array(
                array('type' => 'public-key', 'alg' => -7),    // ES256
                array('type' => 'public-key', 'alg' => -257),  // RS256
                array('type' => 'public-key', 'alg' => -8),    // EdDSA
            ),
            'excludeCredentials' => $exclude,
            'authenticatorSelection' => array(
                'residentKey'      => 'preferred',
                'userVerification'  => 'preferred',
            ),
            'timeout' => self::CHALLENGE_TTL * 1000,
        ));
    }

    public function ajax_register_verify() {
        check_ajax_referer('mbr_passkey_register', 'nonce');
        $user_id = get_current_user_id();
        if (!$user_id || !$this->feature_enabled()) {
            wp_send_json_error(array('message' => 'unavailable'), 400);
        }

        $challenge = $this->take_reg_challenge($user_id);
        if ($challenge === '') {
            wp_send_json_error(array('message' => __('Registration timed out. Please try again.', 'mbr-login-customiser')), 400);
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce checked above.
        $client_data_b64 = isset($_POST['clientDataJSON']) ? sanitize_text_field(wp_unslash($_POST['clientDataJSON'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $att_obj_b64     = isset($_POST['attestationObject']) ? sanitize_text_field(wp_unslash($_POST['attestationObject'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $label           = isset($_POST['label']) ? sanitize_text_field(wp_unslash($_POST['label'])) : '';

        $client_data = $this->b64url_decode($client_data_b64);
        $att_obj_raw = $this->b64url_decode($att_obj_b64);
        if ($client_data === '' || $att_obj_raw === '') {
            wp_send_json_error(array('message' => __('Malformed passkey response.', 'mbr-login-customiser')), 400);
        }

        $cd = json_decode($client_data, true);
        if (!is_array($cd) || ($cd['type'] ?? '') !== 'webauthn.create') {
            wp_send_json_error(array('message' => __('Unexpected passkey response type.', 'mbr-login-customiser')), 400);
        }
        // Challenge must match the one we issued (anti-replay).
        if (!hash_equals($challenge, (string) ($cd['challenge'] ?? ''))) {
            wp_send_json_error(array('message' => __('Challenge mismatch.', 'mbr-login-customiser')), 400);
        }
        // Origin must be this site.
        if (($cd['origin'] ?? '') !== $this->expected_origin()) {
            wp_send_json_error(array('message' => __('Origin mismatch.', 'mbr-login-customiser')), 400);
        }

        // Decode the attestation object and parse the authenticator data.
        try {
            $offset = 0;
            $att    = $this->cbor_decode($att_obj_raw, $offset);
        } catch (Exception $e) {
            wp_send_json_error(array('message' => __('Could not read passkey data.', 'mbr-login-customiser')), 400);
        }
        if (!is_array($att) || !isset($att['authData'])) {
            wp_send_json_error(array('message' => __('Could not read passkey data.', 'mbr-login-customiser')), 400);
        }

        $parsed = $this->parse_authenticator_data($att['authData'], true);
        if (!$parsed) {
            wp_send_json_error(array('message' => __('Invalid authenticator data.', 'mbr-login-customiser')), 400);
        }
        // rpIdHash must be sha256(rpId).
        if (!hash_equals(hash('sha256', $this->rp_id(), true), $parsed['rpIdHash'])) {
            wp_send_json_error(array('message' => __('Relying-party mismatch.', 'mbr-login-customiser')), 400);
        }
        // User must have been present.
        if (!($parsed['flags'] & 0x01)) {
            wp_send_json_error(array('message' => __('User presence was not confirmed.', 'mbr-login-customiser')), 400);
        }
        if (empty($parsed['credId']) || empty($parsed['cose'])) {
            wp_send_json_error(array('message' => __('No credential was returned.', 'mbr-login-customiser')), 400);
        }

        // Reject duplicate credential IDs (across all users).
        $cred_id_b64 = $this->b64url_encode($parsed['credId']);
        if ($this->find_user_by_credential($cred_id_b64)) {
            wp_send_json_error(array('message' => __('That passkey is already registered.', 'mbr-login-customiser')), 400);
        }

        // Sanity-check the key is one we can verify with later.
        if ($this->cose_to_pem($parsed['cose']) === null && !$this->is_okp_ed25519($parsed['cose'])) {
            wp_send_json_error(array('message' => __('Unsupported passkey key type.', 'mbr-login-customiser')), 400);
        }

        $this->add_credential($user_id, array(
            'id'         => $cred_id_b64,
            'cose'       => $this->b64url_encode($this->cbor_encode_cose($parsed['cose'])),
            'signCount'  => (int) $parsed['signCount'],
            'label'      => $label !== '' ? $label : __('Passkey', 'mbr-login-customiser'),
            'created'    => time(),
            'last_used'  => 0,
        ));

        wp_send_json_success(array('message' => __('Passkey registered.', 'mbr-login-customiser')));
    }

    /* =====================================================================
     * AJAX: login ceremony
     * ================================================================== */

    public function ajax_login_options() {
        if (!$this->feature_enabled() || $this->emergency_disabled()) {
            wp_send_json_error(array('message' => 'unavailable'), 400);
        }

        $challenge = $this->b64url_encode(random_bytes(32));
        $chal_id   = bin2hex(random_bytes(16));
        set_transient(self::LOGIN_CHAL_PREFIX . $chal_id, $challenge, self::CHALLENGE_TTL);

        // Discoverable-credential (usernameless) flow: no allowCredentials, the
        // authenticator offers the user's passkeys for this RP.
        wp_send_json_success(array(
            'challenge'        => $challenge,
            'challengeId'      => $chal_id,
            'rpId'             => $this->rp_id(),
            'userVerification' => 'preferred',
            'timeout'          => self::CHALLENGE_TTL * 1000,
        ));
    }

    public function ajax_login_verify() {
        if (!$this->feature_enabled() || $this->emergency_disabled()) {
            wp_send_json_error(array('message' => 'unavailable'), 400);
        }

        $post = wp_unslash($_POST); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- crypto challenge-response is the auth.
        $chal_id = isset($post['challengeId']) ? preg_replace('/[^a-f0-9]/', '', (string) $post['challengeId']) : '';
        $challenge = $chal_id ? get_transient(self::LOGIN_CHAL_PREFIX . $chal_id) : false;
        if ($chal_id) {
            delete_transient(self::LOGIN_CHAL_PREFIX . $chal_id); // one-time
        }
        if (!$challenge) {
            wp_send_json_error(array('message' => __('Sign-in timed out. Please try again.', 'mbr-login-customiser')), 400);
        }

        $cred_id_b64 = isset($post['id']) ? (string) $post['id'] : '';
        $auth_data   = $this->b64url_decode(isset($post['authenticatorData']) ? (string) $post['authenticatorData'] : '');
        $client_data = $this->b64url_decode(isset($post['clientDataJSON']) ? (string) $post['clientDataJSON'] : '');
        $signature   = $this->b64url_decode(isset($post['signature']) ? (string) $post['signature'] : '');
        $user_handle = isset($post['userHandle']) ? (string) $post['userHandle'] : '';

        if ($cred_id_b64 === '' || $auth_data === '' || $client_data === '' || $signature === '') {
            wp_send_json_error(array('message' => __('Malformed passkey response.', 'mbr-login-customiser')), 400);
        }

        // Locate the credential's owner. Prefer the credential ID; fall back to
        // the returned user handle.
        $user_id = $this->find_user_by_credential($cred_id_b64);
        if (!$user_id && $user_handle !== '') {
            $user_id = $this->find_user_by_handle($user_handle);
        }
        if (!$user_id) {
            wp_send_json_error(array('message' => __('Passkey not recognised.', 'mbr-login-customiser')), 400);
        }

        $cred = $this->get_credential($user_id, $cred_id_b64);
        if (!$cred) {
            wp_send_json_error(array('message' => __('Passkey not recognised.', 'mbr-login-customiser')), 400);
        }

        // clientDataJSON checks: type, challenge (anti-replay), origin.
        $cd = json_decode($client_data, true);
        if (!is_array($cd) || ($cd['type'] ?? '') !== 'webauthn.get') {
            wp_send_json_error(array('message' => __('Unexpected passkey response type.', 'mbr-login-customiser')), 400);
        }
        if (!hash_equals($challenge, (string) ($cd['challenge'] ?? ''))) {
            wp_send_json_error(array('message' => __('Challenge mismatch.', 'mbr-login-customiser')), 400);
        }
        if (($cd['origin'] ?? '') !== $this->expected_origin()) {
            wp_send_json_error(array('message' => __('Origin mismatch.', 'mbr-login-customiser')), 400);
        }

        // authenticatorData checks: rpIdHash + user-present flag.
        $parsed = $this->parse_authenticator_data($auth_data, false);
        if (!$parsed) {
            wp_send_json_error(array('message' => __('Invalid authenticator data.', 'mbr-login-customiser')), 400);
        }
        if (!hash_equals(hash('sha256', $this->rp_id(), true), $parsed['rpIdHash'])) {
            wp_send_json_error(array('message' => __('Relying-party mismatch.', 'mbr-login-customiser')), 400);
        }
        if (!($parsed['flags'] & 0x01)) {
            wp_send_json_error(array('message' => __('User presence was not confirmed.', 'mbr-login-customiser')), 400);
        }

        // The signed message is authenticatorData || sha256(clientDataJSON).
        $signed = $auth_data . hash('sha256', $client_data, true);
        $cose   = $this->cbor_decode_cose($this->b64url_decode($cred['cose']));
        if (!$this->verify_signature($cose, $signed, $signature)) {
            wp_send_json_error(array('message' => __('Passkey signature could not be verified.', 'mbr-login-customiser')), 400);
        }

        // Signature-counter check: a non-zero counter that fails to advance is a
        // sign of a cloned authenticator. Zero from either side means the
        // authenticator does not use a counter — accept but do not enforce.
        $stored = (int) $cred['signCount'];
        $now    = (int) $parsed['signCount'];
        if ($stored > 0 && $now > 0 && $now <= $stored) {
            wp_send_json_error(array('message' => __('Passkey counter check failed (possible cloned key).', 'mbr-login-customiser')), 400);
        }
        $this->update_credential_usage($user_id, $cred_id_b64, $now);

        $user = get_user_by('id', $user_id);
        if (!$user) {
            wp_send_json_error(array('message' => __('Account not found.', 'mbr-login-customiser')), 400);
        }

        // 2FA mode: the passkey is the SECOND factor. Don't sign the user in
        // here; hand back a one-time proof token for the password POST instead.
        if ($this->mode() === '2fa') {
            wp_send_json_success(array(
                'twofa'    => true,
                'proof'    => $this->issue_second_factor_proof($user_id),
                'message'  => __('Passkey verified. Complete sign-in with your password.', 'mbr-login-customiser'),
            ));
        }

        // Passwordless mode: complete the login. Firing wp_login routes through
        // the existing success logging and lockout-clearing hooks.
        wp_set_auth_cookie($user->ID, false);
        do_action('wp_login', $user->user_login, $user);

        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $redirect = isset($post['redirectTo']) ? wp_validate_redirect((string) $post['redirectTo'], admin_url()) : admin_url();
        $redirect = apply_filters('login_redirect', $redirect, $redirect, $user);

        wp_send_json_success(array(
            'redirect' => $redirect,
            'message'  => __('Signed in.', 'mbr-login-customiser'),
        ));
    }

    /* =====================================================================
     * Authenticator-data parsing
     * ================================================================== */

    /**
     * Parse the raw authenticatorData structure.
     *
     * Layout: rpIdHash(32) | flags(1) | signCount(4) [ | attestedCredentialData ]
     *   attestedCredentialData = aaguid(16) | credIdLen(2) | credId | COSEKey
     *
     * @param string $data           Raw bytes.
     * @param bool   $expect_cred    True for registration (parse the credential).
     * @return array|false
     */
    private function parse_authenticator_data($data, $expect_cred) {
        if (strlen($data) < 37) {
            return false;
        }
        $rp_id_hash = substr($data, 0, 32);
        $flags      = ord($data[32]);
        $sign_count = unpack('N', substr($data, 33, 4))[1];

        $out = array(
            'rpIdHash'  => $rp_id_hash,
            'flags'     => $flags,
            'signCount' => $sign_count,
            'credId'    => '',
            'cose'      => null,
        );

        if ($expect_cred) {
            // AT flag (0x40) must be set and the attested data must be present.
            if (!($flags & 0x40) || strlen($data) < 55) {
                return false;
            }
            $cred_id_len = unpack('n', substr($data, 53, 2))[1];
            $offset      = 55;
            if (strlen($data) < $offset + $cred_id_len) {
                return false;
            }
            $out['credId'] = substr($data, $offset, $cred_id_len);
            $offset       += $cred_id_len;

            // The remainder begins with the COSE key (CBOR map). Decode it in
            // place; trailing extension bytes, if any, are ignored.
            try {
                $pos        = $offset;
                $out['cose'] = $this->cbor_decode($data, $pos);
            } catch (Exception $e) {
                return false;
            }
            if (!is_array($out['cose'])) {
                return false;
            }
        }

        return $out;
    }

    /* =====================================================================
     * Signature verification (pure PHP, core extensions only)
     * ================================================================== */

    /**
     * Verify a WebAuthn assertion signature against a stored COSE key.
     *
     * @param array  $cose      Decoded COSE_Key map.
     * @param string $signed    The signed message.
     * @param string $signature Raw signature bytes (DER ECDSA for ES256/RS256).
     */
    private function verify_signature($cose, $signed, $signature) {
        if (!is_array($cose)) {
            return false;
        }
        $kty = isset($cose[1]) ? (int) $cose[1] : 0;
        $alg = isset($cose[3]) ? (int) $cose[3] : 0;

        // EdDSA / Ed25519 (OKP).
        if ($kty === 1 && $this->is_okp_ed25519($cose)) {
            if (!function_exists('sodium_crypto_sign_verify_detached')) {
                return false;
            }
            $pk = isset($cose[-2]) ? (string) $cose[-2] : '';
            if (strlen($pk) !== 32) {
                return false;
            }
            return sodium_crypto_sign_verify_detached($signature, $signed, $pk);
        }

        // ES256 / RS256 via OpenSSL.
        $pem = $this->cose_to_pem($cose);
        if ($pem === null) {
            return false;
        }
        $ossl_alg = ($alg === -257) ? OPENSSL_ALGO_SHA256 : OPENSSL_ALGO_SHA256; // both SHA-256
        $ok = openssl_verify($signed, $signature, $pem, $ossl_alg);
        return $ok === 1;
    }

    private function is_okp_ed25519($cose) {
        return is_array($cose)
            && (int) ($cose[1] ?? 0) === 1        // kty OKP
            && (int) ($cose[-1] ?? 0) === 6;      // crv Ed25519
    }

    /**
     * Rebuild an ES256 (EC2/P-256) or RS256 (RSA) COSE key into a PEM public key
     * that OpenSSL accepts. Returns null for unsupported / OKP keys.
     */
    private function cose_to_pem($cose) {
        if (!is_array($cose)) {
            return null;
        }
        $kty = (int) ($cose[1] ?? 0);

        // EC2 / P-256 (ES256).
        if ($kty === 2 && (int) ($cose[-1] ?? 0) === 1) {
            $x = (string) ($cose[-2] ?? '');
            $y = (string) ($cose[-3] ?? '');
            if (strlen($x) !== 32 || strlen($y) !== 32) {
                return null;
            }
            $point = "\x04" . $x . $y;
            // SPKI header for id-ecPublicKey + prime256v1.
            $der = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200') . $point;
            return $this->der_to_pem($der);
        }

        // RSA (RS256).
        if ($kty === 3) {
            $n = (string) ($cose[-1] ?? '');
            $e = (string) ($cose[-2] ?? '');
            if ($n === '' || $e === '') {
                return null;
            }
            $rsa_pub = $this->der_seq(
                $this->der_uint($n) . $this->der_uint($e)
            );
            // SubjectPublicKeyInfo: SEQ { SEQ { rsaEncryption OID, NULL }, BITSTRING(rsaPub) }
            $algo_id = $this->der_seq(
                $this->der_oid_rsa() . "\x05\x00"
            );
            $spki = $this->der_seq($algo_id . $this->der_bitstring($rsa_pub));
            return $this->der_to_pem($spki);
        }

        return null;
    }

    /* --- minimal DER encoders (RSA SPKI construction) --- */

    private function der_len($len) {
        if ($len < 0x80) {
            return chr($len);
        }
        $bytes = '';
        while ($len > 0) {
            $bytes = chr($len & 0xff) . $bytes;
            $len >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private function der_seq($contents) {
        return "\x30" . $this->der_len(strlen($contents)) . $contents;
    }

    /** DER INTEGER for an unsigned big-endian value (adds a leading zero if the top bit is set). */
    private function der_uint($bytes) {
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '') {
            $bytes = "\x00";
        }
        if (ord($bytes[0]) & 0x80) {
            $bytes = "\x00" . $bytes;
        }
        return "\x02" . $this->der_len(strlen($bytes)) . $bytes;
    }

    private function der_bitstring($contents) {
        // Leading 0x00 = zero unused bits.
        return "\x03" . $this->der_len(strlen($contents) + 1) . "\x00" . $contents;
    }

    private function der_oid_rsa() {
        // OID 1.2.840.113549.1.1.1 (rsaEncryption), pre-encoded.
        return hex2bin('06092a864886f70d010101');
    }

    private function der_to_pem($der) {
        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    /* =====================================================================
     * Minimal CBOR (decode enough for COSE keys + attestation objects)
     * ================================================================== */

    /**
     * @param string $b Buffer.
     * @param int    $o Offset (by reference; advanced past the decoded item).
     * @return mixed
     * @throws Exception on unsupported input.
     */
    private function cbor_decode($b, &$o) {
        if (!isset($b[$o])) {
            throw new Exception('cbor: unexpected end');
        }
        $ib = ord($b[$o++]);
        $mt = $ib >> 5;
        $ai = $ib & 0x1f;
        $val = $this->cbor_read_uint($b, $o, $ai);

        switch ($mt) {
            case 0: // unsigned int
                return $val;
            case 1: // negative int
                return -1 - $val;
            case 2: // byte string
            case 3: // text string
                $s = substr($b, $o, $val);
                $o += $val;
                return $s;
            case 4: // array
                $arr = array();
                for ($i = 0; $i < $val; $i++) {
                    $arr[] = $this->cbor_decode($b, $o);
                }
                return $arr;
            case 5: // map
                $map = array();
                for ($i = 0; $i < $val; $i++) {
                    $k = $this->cbor_decode($b, $o);
                    $map[$k] = $this->cbor_decode($b, $o);
                }
                return $map;
            case 6: // tag: skip the tag, return the tagged item
                return $this->cbor_decode($b, $o);
            case 7: // simple / float — accept false/true/null only
                if ($ai === 20) { return false; }
                if ($ai === 21) { return true; }
                if ($ai === 22 || $ai === 23) { return null; }
                throw new Exception('cbor: unsupported simple value');
        }
        throw new Exception('cbor: unsupported major type');
    }

    private function cbor_read_uint($b, &$o, $ai) {
        if ($ai < 24) {
            return $ai;
        }
        if ($ai === 24) {
            $v = ord($b[$o]); $o += 1; return $v;
        }
        if ($ai === 25) {
            $v = unpack('n', substr($b, $o, 2))[1]; $o += 2; return $v;
        }
        if ($ai === 26) {
            $v = unpack('N', substr($b, $o, 4))[1]; $o += 4; return $v;
        }
        if ($ai === 27) {
            // 64-bit. PHP ints are 64-bit on the target; use unpack('J') where available.
            $hi = unpack('N', substr($b, $o, 4))[1];
            $lo = unpack('N', substr($b, $o + 4, 4))[1];
            $o += 8;
            return ($hi << 32) | $lo;
        }
        throw new Exception('cbor: bad length');
    }

    /**
     * Re-encode a decoded COSE key map to canonical-enough CBOR for storage.
     * Only the integer-keyed entries we use are emitted (kty, alg, crv, x, y / n, e).
     */
    private function cbor_encode_cose($cose) {
        // Preserve the map exactly by re-encoding each key/value we understand.
        $keys = array();
        foreach ($cose as $k => $v) {
            $keys[] = $k;
        }
        $out = $this->cbor_encode_uint(5, count($keys)); // map header
        foreach ($cose as $k => $v) {
            $out .= $this->cbor_encode_int($k);
            if (is_int($v)) {
                $out .= $this->cbor_encode_int($v);
            } else {
                $out .= $this->cbor_encode_bstr((string) $v);
            }
        }
        return $out;
    }

    private function cbor_decode_cose($raw) {
        $o = 0;
        return $this->cbor_decode($raw, $o);
    }

    private function cbor_encode_uint($mt, $val) {
        if ($val < 24) {
            return chr(($mt << 5) | $val);
        }
        if ($val < 0x100) {
            return chr(($mt << 5) | 24) . chr($val);
        }
        if ($val < 0x10000) {
            return chr(($mt << 5) | 25) . pack('n', $val);
        }
        return chr(($mt << 5) | 26) . pack('N', $val);
    }

    private function cbor_encode_int($val) {
        if ($val >= 0) {
            return $this->cbor_encode_uint(0, $val);
        }
        return $this->cbor_encode_uint(1, -1 - $val);
    }

    private function cbor_encode_bstr($s) {
        return $this->cbor_encode_uint(2, strlen($s)) . $s;
    }

    /* =====================================================================
     * Credential storage (user meta)
     * ================================================================== */

    public function get_credentials($user_id) {
        $creds = get_user_meta($user_id, self::CRED_META, true);
        return is_array($creds) ? $creds : array();
    }

    public function get_credential($user_id, $cred_id_b64) {
        foreach ($this->get_credentials($user_id) as $c) {
            if (hash_equals((string) $c['id'], (string) $cred_id_b64)) {
                return $c;
            }
        }
        return null;
    }

    private function add_credential($user_id, array $cred) {
        $creds   = $this->get_credentials($user_id);
        $creds[] = $cred;
        update_user_meta($user_id, self::CRED_META, $creds);
    }

    public function delete_credential($user_id, $cred_id_b64) {
        $creds = $this->get_credentials($user_id);
        $kept  = array();
        foreach ($creds as $c) {
            if (!hash_equals((string) $c['id'], (string) $cred_id_b64)) {
                $kept[] = $c;
            }
        }
        update_user_meta($user_id, self::CRED_META, $kept);
    }

    private function update_credential_usage($user_id, $cred_id_b64, $new_count) {
        $creds = $this->get_credentials($user_id);
        foreach ($creds as &$c) {
            if (hash_equals((string) $c['id'], (string) $cred_id_b64)) {
                if ($new_count > (int) $c['signCount']) {
                    $c['signCount'] = (int) $new_count;
                }
                $c['last_used'] = time();
                break;
            }
        }
        unset($c);
        update_user_meta($user_id, self::CRED_META, $creds);
    }

    public function disable_for_user($user_id) {
        delete_user_meta($user_id, self::CRED_META);
        delete_user_meta($user_id, self::HANDLE_META);
    }

    /** Find the user ID that owns a credential ID, or 0. */
    public function find_user_by_credential($cred_id_b64) {
        global $wpdb;
        // The credential ID is embedded in the serialised meta array; a LIKE on
        // the serialised value narrows the candidates, then we confirm in PHP.
        $like    = '%' . $wpdb->esc_like($cred_id_b64) . '%';
        $user_ids = $wpdb->get_col($wpdb->prepare(
            "SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value LIKE %s",
            self::CRED_META,
            $like
        ));
        foreach ($user_ids as $uid) {
            if ($this->get_credential($uid, $cred_id_b64)) {
                return (int) $uid;
            }
        }
        return 0;
    }

    public function find_user_by_handle($handle_b64) {
        $users = get_users(array(
            'meta_key'   => self::HANDLE_META,
            'meta_value' => $handle_b64,
            'fields'     => 'ID',
            'number'     => 1,
        ));
        return !empty($users) ? (int) $users[0] : 0;
    }

    private function get_or_create_handle($user_id) {
        $handle = get_user_meta($user_id, self::HANDLE_META, true);
        if (!$handle) {
            $handle = $this->b64url_encode(random_bytes(32));
            update_user_meta($user_id, self::HANDLE_META, $handle);
        }
        return $handle;
    }

    public function count_enrolled_users() {
        $users = get_users(array(
            'meta_key'     => self::CRED_META,
            'meta_compare' => 'EXISTS',
            'fields'       => 'ID',
            'number'       => 1000,
        ));
        return count($users);
    }

    /* =====================================================================
     * base64url
     * ================================================================== */

    private function b64url_encode($bin) {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    private function b64url_decode($s) {
        $s = strtr((string) $s, '-_', '+/');
        $pad = strlen($s) % 4;
        if ($pad) {
            $s .= str_repeat('=', 4 - $pad);
        }
        $out = base64_decode($s, true);
        return $out === false ? '' : $out;
    }

    /* =====================================================================
     * Profile enrolment UI
     * ================================================================== */

    public function enqueue_profile_assets($hook) {
        if (!in_array($hook, array('profile.php', 'user-edit.php'), true)) {
            return;
        }
        if (!$this->feature_enabled() || $this->emergency_disabled()) {
            return;
        }
        wp_enqueue_script(
            'mbr-passkeys',
            MBR_CUSTOM_LOGIN_PLUGIN_URL . 'passkeys.js',
            array(),
            $this->asset_version(),
            true
        );
        wp_localize_script('mbr-passkeys', 'mbrPasskeys', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce'   => wp_create_nonce('mbr_passkey_register'),
            'context' => 'profile',
            'i18n'    => array(
                'unsupported' => __('This browser does not support passkeys.', 'mbr-login-customiser'),
                'failed'      => __('Passkey registration failed. Please try again.', 'mbr-login-customiser'),
                'cancelled'   => __('Passkey registration was cancelled.', 'mbr-login-customiser'),
                'working'     => __('Follow your device’s prompt…', 'mbr-login-customiser'),
                'registered'  => __('Passkey registered. Reload to see it listed.', 'mbr-login-customiser'),
                'namePrompt'  => __('Name this passkey (e.g. “Work laptop”):', 'mbr-login-customiser'),
            ),
        ));
    }

    public function render_profile_section($user) {
        if (!$this->feature_enabled() || $this->emergency_disabled()) {
            return;
        }
        if (!is_object($user) || empty($user->ID)) {
            return;
        }
        $is_own = (get_current_user_id() === (int) $user->ID);
        $creds  = $this->get_credentials($user->ID);

        echo '<h2>' . esc_html__('Passkeys', 'mbr-login-customiser') . '</h2>';
        echo '<table class="form-table" role="presentation"><tbody>';

        // Registered passkeys list.
        echo '<tr><th>' . esc_html__('Registered passkeys', 'mbr-login-customiser') . '</th><td>';
        if (empty($creds)) {
            echo '<p class="description">' . esc_html__('None yet.', 'mbr-login-customiser') . '</p>';
        } else {
            echo '<ul style="margin:0;">';
            foreach ($creds as $c) {
                $when = $c['created'] ? date_i18n(get_option('date_format'), (int) $c['created']) : '';
                echo '<li style="margin-bottom:6px;">';
                echo '<strong>' . esc_html($c['label']) . '</strong> ';
                if ($when) {
                    echo '<span class="description">' . sprintf(
                        /* translators: %s: date the passkey was added */
                        esc_html__('(added %s)', 'mbr-login-customiser'),
                        esc_html($when)
                    ) . '</span> ';
                }
                echo '<label style="margin-left:8px;"><input type="checkbox" name="mbr_passkey_remove[]" value="' . esc_attr($c['id']) . '"> ' . esc_html__('Remove', 'mbr-login-customiser') . '</label>';
                echo '</li>';
            }
            echo '</ul>';
            echo '<p class="description">' . esc_html__('Tick “Remove” and save your profile to delete a passkey.', 'mbr-login-customiser') . '</p>';
        }
        echo '</td></tr>';

        if ($is_own) {
            echo '<tr><th>' . esc_html__('Add a passkey', 'mbr-login-customiser') . '</th><td>';
            echo '<button type="button" class="button button-secondary" id="mbr-passkey-register">' . esc_html__('Register a passkey', 'mbr-login-customiser') . '</button>';
            echo '<p id="mbr-passkey-reg-status" class="description" role="status" aria-live="polite" style="margin-top:8px;"></p>';
            echo '<p class="description" style="max-width:640px;">' . esc_html__('Use your device’s fingerprint, face, screen lock, or a hardware security key. The passkey is created on your device — the private key never leaves it.', 'mbr-login-customiser') . '</p>';
            echo '</td></tr>';
        } else {
            echo '<tr><th>' . esc_html__('Add a passkey', 'mbr-login-customiser') . '</th><td><p class="description">' . esc_html__('A user can only register a passkey on their own profile.', 'mbr-login-customiser') . '</p></td></tr>';
        }

        echo '</tbody></table>';
    }

    public function save_profile($user_id) {
        if (!$this->feature_enabled() || $this->emergency_disabled()) {
            return;
        }
        if (!current_user_can('edit_user', $user_id)) {
            return;
        }
        // Removal is allowed for your own passkeys or (for admins) another user's.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- rides the core profile-update nonce.
        if (!empty($_POST['mbr_passkey_remove']) && is_array($_POST['mbr_passkey_remove'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $remove = array_map('sanitize_text_field', wp_unslash($_POST['mbr_passkey_remove']));
            foreach ($remove as $cred_id) {
                $this->delete_credential($user_id, $cred_id);
            }
        }
    }

    /* =====================================================================
     * Admin settings tab (rendered from the admin screen dispatcher)
     * ================================================================== */

    public function render_settings_tab() {
        $enabled = (bool) get_option('mbr_custom_login_passkeys_enabled', 0);
        $mode    = $this->mode();
        $count   = $this->count_enrolled_users();
        ?>
        <form method="post" action="options.php" style="margin-top:1em;">
            <?php settings_fields('mbr_custom_login_passkeys'); ?>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><?php esc_html_e('Enable passkeys', 'mbr-login-customiser'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="mbr_custom_login_passkeys_enabled" value="1" <?php checked($enabled); ?>>
                            <?php esc_html_e('Let users sign in with a passkey (WebAuthn / FIDO2).', 'mbr-login-customiser'); ?>
                        </label>
                        <p class="description">
                            <?php
                            printf(
                                /* translators: %d: number of users with a passkey */
                                esc_html(_n('%d user has a passkey registered.', '%d users have a passkey registered.', $count, 'mbr-login-customiser')),
                                (int) $count
                            );
                            ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e('Mode', 'mbr-login-customiser'); ?></th>
                    <td>
                        <select name="mbr_custom_login_passkeys_mode">
                            <option value="passwordless" <?php selected($mode, 'passwordless'); ?>><?php esc_html_e('Passwordless — a “Sign in with a passkey” button alongside the password form (recommended)', 'mbr-login-customiser'); ?></option>
                            <option value="2fa" <?php selected($mode, '2fa'); ?>><?php esc_html_e('Second factor — require a passkey after the password for users who have one', 'mbr-login-customiser'); ?></option>
                        </select>
                        <p class="description">
                            <?php esc_html_e('Passwordless mode never blocks the normal password login, so it cannot lock anyone out. Second-factor mode is stricter: a user who has registered a passkey must present it after their password.', 'mbr-login-customiser'); ?>
                        </p>
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>

        <h2><?php esc_html_e('How it works', 'mbr-login-customiser'); ?></h2>
        <p class="description" style="max-width:680px;">
            <?php
            printf(
                /* translators: %s: link to Users > Profile */
                esc_html__('Once enabled, each user registers a passkey from %s using their device biometrics, screen lock, or a hardware key. Everything is verified on your server in PHP — no external services are contacted.', 'mbr-login-customiser'),
                '<a href="' . esc_url(admin_url('profile.php')) . '">' . esc_html__('Users → Profile', 'mbr-login-customiser') . '</a>'
            );
            ?>
        </p>
        <p class="description" style="max-width:680px;">
            <?php esc_html_e('Passkeys require an HTTPS site. To switch the feature off everywhere in an emergency, add this line to wp-config.php:', 'mbr-login-customiser'); ?>
            <br><code>define('MBR_LOGIN_PASSKEYS_DISABLE', true);</code>
        </p>
        <?php
    }
}
