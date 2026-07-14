<?php
/**
 * Login Firewall: request-level protection in front of the login page.
 *
 * The existing security stack (blacklist, schedule, lockouts) operates on the
 * 'authenticate' chain, which only runs once credentials have been submitted.
 * This module sits in front of all of that, on the request itself, so known
 * nasties never reach the login form at all:
 *
 *  1. Request gate     - blacklisted, locked-out and firewall-blocked IPs get
 *                        a 403 before the form renders (and in exclusive
 *                        whitelist-only mode, so does everyone off the list).
 *  2. Bad bot filter   - requests with an empty User-Agent, or one matching a
 *                        known script/scanner signature, get a 403.
 *  3. Rate limiter     - more than N hits on the login page within a window
 *                        earns the IP a temporary firewall block.
 *  4. Honeypot         - an invisible form field; anything that fills it is a
 *                        bot and is blocked instantly.
 *  5. Minimum fill time- a signed timestamp proves the form was rendered at
 *                        least N seconds before submission; bots that POST
 *                        credentials instantly (or without ever loading the
 *                        form) are refused.
 *
 * Everything is pure PHP with no external services, matching the rest of the
 * plugin. Whitelisted IPs and logged-in users bypass the request-level checks.
 *
 * Recovery: define('MBR_LOGIN_FIREWALL_DISABLE', true) in wp-config.php turns
 * the whole module off, mirroring the passkeys kill switch.
 *
 * @package MBR_Login_Customiser
 */

if (!defined('ABSPATH')) {
    exit;
}

class MBR_Login_Firewall {

    /**
     * Honeypot field name. Deliberately tempting to form-filling bots.
     */
    const HONEYPOT_FIELD = 'mbr_url_website';

    /**
     * Signed render-timestamp field name.
     */
    const TIMESTAMP_FIELD = 'mbr_fw_ts';

    /**
     * Transient prefixes (suffixed with a hash of the IP).
     */
    const HITS_TRANSIENT  = 'mbr_fw_hits_';
    const BLOCK_TRANSIENT = 'mbr_fw_block_';

    /**
     * User-Agent substrings that identify scripts and scanners, not browsers.
     * Deliberately conservative: every entry is a tool that has no business
     * loading a login form. Matched case-insensitively.
     */
    private $bad_agents = array(
        'curl', 'wget', 'python-requests', 'python-urllib', 'libwww-perl',
        'go-http-client', 'okhttp', 'scrapy', 'httpclient', 'httpunit',
        'nikto', 'sqlmap', 'masscan', 'zgrab', 'nmap', 'dirbuster',
        'hydra', 'wpscan', 'fimap', 'nessus',
    );

    /**
     * Register WordPress hooks for this module.
     */
    public function register_hooks() {
        if (defined('MBR_LOGIN_FIREWALL_DISABLE') && MBR_LOGIN_FIREWALL_DISABLE) {
            return;
        }

        // Request-level checks: run as the login page begins executing,
        // before any form is rendered or any credential is examined.
        add_action('login_init', array($this, 'guard_request'), 1);

        // Hidden honeypot + signed timestamp fields inside the login form.
        add_action('login_form', array($this, 'render_hidden_fields'));

        // Form-level checks: priority 90, ahead of the access gate (95) and
        // the lockout check (99), so a bot submission is refused before it
        // can even count as a "failed login".
        add_filter('authenticate', array($this, 'check_submission'), 90, 3);

        // Optionally close the XML-RPC authentication side door.
        if ($this->enabled() && get_option('mbr_custom_login_firewall_block_xmlrpc', 0)) {
            add_filter('xmlrpc_enabled', '__return_false');
        }
    }

    /**
     * Is the firewall switched on?
     */
    public function enabled() {
        if (defined('MBR_LOGIN_FIREWALL_DISABLE') && MBR_LOGIN_FIREWALL_DISABLE) {
            return false;
        }
        return (bool) get_option('mbr_custom_login_firewall_enabled', 0);
    }

    /* ---------------------------------------------------------------------
     * Layer 1-3: the request gate (login_init)
     * ------------------------------------------------------------------ */

    /**
     * Runs on every hit to the login page, before anything renders.
     */
    public function guard_request() {
        if (!$this->enabled()) {
            return;
        }

        // Logged-in users (reauth, logout confirmations) are never firewalled.
        if (is_user_logged_in()) {
            return;
        }

        $ip = MBR_Login_Security::get_client_ip();

        // Trusted IPs bypass every request-level check.
        if (MBR_Login_Access::is_whitelisted($ip)) {
            return;
        }

        // Layer 1: request gate. Anyone the authentication layer would refuse
        // anyway is turned away before the form is even served.
        if (get_option('mbr_custom_login_firewall_gate', 1)) {
            if ($this->is_blocked($ip)) {
                $this->deny($ip, 'rate');
            }
            if (MBR_Login_Access::is_blacklisted($ip)) {
                $this->deny($ip, 'blacklist');
            }
            if (MBR_Login_Access::is_exclusive_mode()) {
                // Not whitelisted (checked above) and exclusive mode is on.
                $this->deny($ip, 'exclusive');
            }
            if ($this->is_locked_out($ip)) {
                $this->deny($ip, 'lockout');
            }
        }

        // Layer 2: bad bot filter.
        if (get_option('mbr_custom_login_firewall_bad_agents', 1)) {
            $agent = isset($_SERVER['HTTP_USER_AGENT'])
                ? trim((string) wp_unslash($_SERVER['HTTP_USER_AGENT']))
                : '';

            if ($agent === '') {
                $this->deny($ip, 'no-agent');
            }

            $agent_lc = strtolower($agent);
            foreach ($this->bad_agents as $needle) {
                if (strpos($agent_lc, $needle) !== false) {
                    $this->deny($ip, 'bad-agent');
                }
            }
        }

        // Layer 3: page-hit rate limiter.
        if (get_option('mbr_custom_login_firewall_rate_enabled', 1)) {
            $this->count_hit($ip);
        }
    }

    /**
     * Does the security module currently have this IP locked out?
     *
     * Reads the same option row the lockout module maintains; the md5 key
     * matches MBR_Login_Security::ip_key().
     */
    private function is_locked_out($ip) {
        $data = get_option(MBR_Login_Security::ATTEMPT_OPTION, array());
        if (!is_array($data)) {
            return false;
        }
        $key = md5($ip);
        return !empty($data[$key]['lock_until']) && $data[$key]['lock_until'] > time();
    }

    /**
     * Is this IP under an active firewall block (rate limit / honeypot trip)?
     */
    public function is_blocked($ip) {
        return (bool) get_transient(self::BLOCK_TRANSIENT . md5($ip));
    }

    /**
     * Record a login-page hit and block the IP once the ceiling is crossed.
     */
    private function count_hit($ip) {
        $max    = max(1, (int) get_option('mbr_custom_login_firewall_rate_max', 20));
        $window = max(5, (int) get_option('mbr_custom_login_firewall_rate_window', 60));

        $key  = self::HITS_TRANSIENT . md5($ip);
        $hits = (int) get_transient($key);
        $hits++;

        // The window restarts with each transient write; for a flood detector
        // that slight extension is fine and keeps this to one storage row.
        set_transient($key, $hits, $window);

        if ($hits > $max) {
            $this->block_ip($ip, 'rate');
            $this->deny($ip, 'rate');
        }
    }

    /**
     * Put an IP under a temporary firewall block and log/announce it once.
     */
    private function block_ip($ip, $reason) {
        $minutes = max(1, (int) get_option('mbr_custom_login_firewall_rate_block', 10));
        $key     = self::BLOCK_TRANSIENT . md5($ip);

        // Only log the moment the block starts, not every refused hit after.
        if (!get_transient($key)) {
            /**
             * Fires when the login firewall blocks an IP. The log module
             * listens for this to record a 'firewall' event.
             *
             * @param string $ip       The (already resolved) client IP.
             * @param string $username Submitted username, if any.
             * @param string $reason   Machine reason: rate|honeypot|timing.
             */
            do_action('mbr_login_customiser_firewall', $ip, '', $reason);
        }

        set_transient($key, time() + ($minutes * MINUTE_IN_SECONDS), $minutes * MINUTE_IN_SECONDS);
    }

    /**
     * Refuse the request with a neutral 403 and stop.
     */
    private function deny($ip, $reason) {
        // Page-level refusals for pre-existing states (blacklist, lockout,
        // exclusive mode) are already visible in the log through their own
        // events, so only firewall-specific reasons are announced here.
        if (in_array($reason, array('no-agent', 'bad-agent'), true)) {
            do_action('mbr_login_customiser_firewall', $ip, '', $reason);
        }

        wp_die(
            esc_html__('Access denied.', 'mbr-login-customiser'),
            esc_html__('Access denied', 'mbr-login-customiser'),
            array('response' => 403)
        );
    }

    /* ---------------------------------------------------------------------
     * Layer 4-5: form-level checks (honeypot + minimum fill time)
     * ------------------------------------------------------------------ */

    /**
     * login_form: output the honeypot and the signed render timestamp.
     */
    public function render_hidden_fields() {
        if (!$this->enabled()) {
            return;
        }

        if (get_option('mbr_custom_login_firewall_honeypot', 1)) {
            // Hidden from humans (offscreen, unfocusable, ignored by screen
            // readers) but present in the DOM where autofill bots find it.
            printf(
                '<div style="position:absolute;left:-9999px;top:-9999px;" aria-hidden="true">' .
                '<label for="%1$s">%2$s</label>' .
                '<input type="text" name="%1$s" id="%1$s" value="" tabindex="-1" autocomplete="off"></div>',
                esc_attr(self::HONEYPOT_FIELD),
                esc_html__('Leave this field empty', 'mbr-login-customiser')
            );
        }

        if ((int) get_option('mbr_custom_login_firewall_min_time', 2) > 0) {
            $ts = time();
            printf(
                '<input type="hidden" name="%s" value="%s">',
                esc_attr(self::TIMESTAMP_FIELD),
                esc_attr($ts . '|' . $this->sign_timestamp($ts))
            );
        }
    }

    /**
     * HMAC for the render timestamp so a bot cannot mint its own.
     */
    private function sign_timestamp($ts) {
        return hash_hmac('sha256', 'mbr-fw|' . $ts, wp_salt('auth'));
    }

    /**
     * authenticate filter (priority 90): refuse bot submissions.
     *
     * Scoped strictly to POSTs handled by wp-login.php itself, so front-end
     * login forms (themes, WooCommerce, custom wp_signon() flows) that never
     * carried our hidden fields are completely unaffected.
     */
    public function check_submission($user, $username, $password) {
        if (!$this->enabled()) {
            return $user;
        }
        if (empty($username) && empty($password)) {
            return $user;
        }
        // Only the real login page carries our fields.
        if (!isset($GLOBALS['pagenow']) || $GLOBALS['pagenow'] !== 'wp-login.php') {
            return $user;
        }
        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
            return $user;
        }

        $ip = MBR_Login_Security::get_client_ip();
        if (MBR_Login_Access::is_whitelisted($ip)) {
            return $user;
        }

        // Layer 4: honeypot. A value here means a bot filled the form.
        if (get_option('mbr_custom_login_firewall_honeypot', 1)) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- pre-auth bot check; the login form has no nonce.
            if (!empty($_POST[self::HONEYPOT_FIELD])) {
                $this->block_ip($ip, 'honeypot');
                return $this->refuse();
            }
        }

        // Layer 5: minimum fill time. The form must have been rendered, and
        // rendered at least N seconds before this submission.
        $min = (int) get_option('mbr_custom_login_firewall_min_time', 2);
        if ($min > 0) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- pre-auth bot check; the login form has no nonce.
            $raw   = isset($_POST[self::TIMESTAMP_FIELD]) ? (string) wp_unslash($_POST[self::TIMESTAMP_FIELD]) : '';
            $parts = explode('|', $raw, 2);
            $valid = false;

            if (count($parts) === 2 && ctype_digit($parts[0])) {
                $ts = (int) $parts[0];
                if (hash_equals($this->sign_timestamp($ts), $parts[1]) && (time() - $ts) >= $min) {
                    $valid = true;
                }
            }

            if (!$valid) {
                do_action('mbr_login_customiser_firewall', $ip, $username, 'timing');
                return $this->refuse();
            }
        }

        return $user;
    }

    /**
     * A neutral refusal that gives an attacker nothing to learn from.
     */
    private function refuse() {
        return new WP_Error(
            'mbr_login_firewall',
            __('<strong>Access denied.</strong> Your request could not be verified. Please reload the page and try again.', 'mbr-login-customiser')
        );
    }

    /* ---------------------------------------------------------------------
     * Settings tab
     * ------------------------------------------------------------------ */

    /**
     * Render the Firewall settings tab (dispatched from the admin screen).
     */
    public function render_settings_tab() {
        $enabled      = (bool) get_option('mbr_custom_login_firewall_enabled', 0);
        $gate         = (bool) get_option('mbr_custom_login_firewall_gate', 1);
        $bad_agents   = (bool) get_option('mbr_custom_login_firewall_bad_agents', 1);
        $rate_enabled = (bool) get_option('mbr_custom_login_firewall_rate_enabled', 1);
        $rate_max     = (int) get_option('mbr_custom_login_firewall_rate_max', 20);
        $rate_window  = (int) get_option('mbr_custom_login_firewall_rate_window', 60);
        $rate_block   = (int) get_option('mbr_custom_login_firewall_rate_block', 10);
        $honeypot     = (bool) get_option('mbr_custom_login_firewall_honeypot', 1);
        $min_time     = (int) get_option('mbr_custom_login_firewall_min_time', 2);
        $xmlrpc       = (bool) get_option('mbr_custom_login_firewall_block_xmlrpc', 0);
        $killed       = defined('MBR_LOGIN_FIREWALL_DISABLE') && MBR_LOGIN_FIREWALL_DISABLE;
        ?>
        <p style="max-width:720px;">
            <?php esc_html_e('The firewall works in front of the login page itself. Blocked visitors are refused before the form is served, bots are caught by traps they cannot see, and floods of requests are throttled - all before a single password is checked. Whitelisted IPs always bypass every firewall check.', 'mbr-login-customiser'); ?>
        </p>

        <?php if ($killed) : ?>
            <div class="notice notice-warning inline"><p>
                <?php esc_html_e('The firewall is currently disabled by the MBR_LOGIN_FIREWALL_DISABLE constant in wp-config.php.', 'mbr-login-customiser'); ?>
            </p></div>
        <?php endif; ?>

        <form method="post" action="options.php" style="margin-top:1em;">
            <?php settings_fields('mbr_custom_login_firewall'); ?>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><?php esc_html_e('Enable firewall', 'mbr-login-customiser'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="mbr_custom_login_firewall_enabled" value="1" <?php checked($enabled); ?>>
                            <?php esc_html_e('Protect the login page with the request-level firewall.', 'mbr-login-customiser'); ?>
                        </label>
                        <p class="description"><?php esc_html_e("Emergency off switch: define('MBR_LOGIN_FIREWALL_DISABLE', true); in wp-config.php.", 'mbr-login-customiser'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e('Request gate', 'mbr-login-customiser'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="mbr_custom_login_firewall_gate" value="1" <?php checked($gate); ?>>
                            <?php esc_html_e('Refuse the login page (HTTP 403) to blacklisted, locked-out and rate-blocked IPs.', 'mbr-login-customiser'); ?>
                        </label>
                        <p class="description"><?php esc_html_e('Without the gate, these IPs can still load the form and are only refused when they try to sign in. Note: while refused, an IP also cannot reach the lost-password form.', 'mbr-login-customiser'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e('Bad bot filter', 'mbr-login-customiser'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="mbr_custom_login_firewall_bad_agents" value="1" <?php checked($bad_agents); ?>>
                            <?php esc_html_e('Refuse requests with no User-Agent, or one matching a known script or scanner (curl, sqlmap, WPScan, and similar).', 'mbr-login-customiser'); ?>
                        </label>
                        <p class="description"><?php esc_html_e('Real browsers always send a User-Agent. Disable this if you rely on an uptime monitor that fetches the login page with a script.', 'mbr-login-customiser'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e('Rate limiting', 'mbr-login-customiser'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="mbr_custom_login_firewall_rate_enabled" value="1" <?php checked($rate_enabled); ?>>
                            <?php esc_html_e('Temporarily block IPs that hammer the login page.', 'mbr-login-customiser'); ?>
                        </label>
                        <p style="margin-top:8px;">
                        <?php
                        printf(
                            /* translators: 1: number input for requests, 2: number input for seconds, 3: number input for minutes */
                            esc_html__('Block after more than %1$s requests within %2$s seconds, for %3$s minutes.', 'mbr-login-customiser'),
                            '<input type="number" min="1" name="mbr_custom_login_firewall_rate_max" value="' . esc_attr($rate_max) . '" style="width:80px;">',
                            '<input type="number" min="5" name="mbr_custom_login_firewall_rate_window" value="' . esc_attr($rate_window) . '" style="width:80px;">',
                            '<input type="number" min="1" name="mbr_custom_login_firewall_rate_block" value="' . esc_attr($rate_block) . '" style="width:80px;">'
                        );
                        ?>
                        </p>
                        <p class="description"><?php esc_html_e('This counts page requests, not failed passwords - it stops floods that never even submit the form. The defaults are generous enough for shared office IPs.', 'mbr-login-customiser'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e('Honeypot', 'mbr-login-customiser'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="mbr_custom_login_firewall_honeypot" value="1" <?php checked($honeypot); ?>>
                            <?php esc_html_e('Add an invisible field to the login form. Humans never see it; a bot that fills it is refused and blocked immediately.', 'mbr-login-customiser'); ?>
                        </label>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="mbr_custom_login_firewall_min_time"><?php esc_html_e('Minimum fill time', 'mbr-login-customiser'); ?></label></th>
                    <td>
                        <input type="number" min="0" max="30" id="mbr_custom_login_firewall_min_time" name="mbr_custom_login_firewall_min_time" value="<?php echo esc_attr($min_time); ?>" style="width:80px;"> <?php esc_html_e('seconds (0 = off)', 'mbr-login-customiser'); ?>
                        <p class="description"><?php esc_html_e('The form carries a signed timestamp proving when it was rendered. Submissions faster than a human could type - or that never loaded the form at all - are refused. Applies only to the wp-login.php form; front-end login forms are unaffected.', 'mbr-login-customiser'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e('XML-RPC authentication', 'mbr-login-customiser'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="mbr_custom_login_firewall_block_xmlrpc" value="1" <?php checked($xmlrpc); ?>>
                            <?php esc_html_e('Disable XML-RPC methods that require authentication.', 'mbr-login-customiser'); ?>
                        </label>
                        <p class="description"><?php esc_html_e('xmlrpc.php is a favourite brute-force side door because it bypasses the login page entirely. Leave this off if you use Jetpack or the WordPress mobile apps, which sign in through XML-RPC.', 'mbr-login-customiser'); ?></p>
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
    }
}
