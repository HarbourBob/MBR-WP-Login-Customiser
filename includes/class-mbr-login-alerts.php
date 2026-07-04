<?php
/**
 * Security alerts.
 *
 * Turns the passive login log into active notifications. Sends an email and/or
 * a webhook (Slack/Discord-compatible) when something worth knowing happens:
 *
 *   - an IP is locked out by the rate limiter,
 *   - an administrator signs in from an IP not seen before,
 *   - failed logins spike above a threshold within a short window.
 *
 * It hooks the same events the log module already emits, so it adds no new
 * probing of its own. Each alert type has a cooldown so an ongoing attack
 * can't flood the inbox.
 *
 * @package MBR_Login_Customiser
 */

if (!defined('ABSPATH')) {
    exit;
}

class MBR_Login_Alerts {

    /** User meta: hashed IPs an administrator has previously signed in from. */
    const KNOWN_IPS_META = 'mbr_known_ips';

    /** Cap on how many known IPs we retain per user. */
    const KNOWN_IPS_MAX = 25;

    public function register_hooks() {
        add_action('mbr_login_customiser_lockout', array($this, 'on_lockout'), 30, 2);
        add_action('wp_login', array($this, 'on_login'), 30, 2);
        add_action('wp_login_failed', array($this, 'on_failed'), 30, 1);
    }

    /* =====================================================================
     * Configuration
     * ================================================================== */

    public function enabled() {
        return (bool) get_option('mbr_custom_login_alerts_enabled', 0);
    }

    private function email_to() {
        $addr = trim((string) get_option('mbr_custom_login_alerts_email', ''));
        if ($addr === '' || !is_email($addr)) {
            $addr = get_option('admin_email');
        }
        return $addr;
    }

    private function webhook_url() {
        $url = trim((string) get_option('mbr_custom_login_alerts_webhook', ''));
        return ($url !== '' && wp_http_validate_url($url)) ? $url : '';
    }

    private function cooldown_seconds() {
        $mins = (int) get_option('mbr_custom_login_alerts_cooldown', 15);
        return max(1, $mins) * MINUTE_IN_SECONDS;
    }

    /* =====================================================================
     * Event handlers
     * ================================================================== */

    /**
     * An IP was locked out by the rate limiter.
     *
     * @param string $ip
     * @param string $username
     */
    public function on_lockout($ip, $username) {
        if (!$this->enabled() || !get_option('mbr_custom_login_alerts_on_lockout', 1)) {
            return;
        }
        if ($this->on_cooldown('lockout', $ip)) {
            return;
        }
        $this->send_alert(
            __('Login lockout triggered', 'mbr-login-customiser'),
            array(
                __('An IP address has been locked out after repeated failed logins.', 'mbr-login-customiser'),
                '',
                sprintf(/* translators: %s: IP address */ __('IP address: %s', 'mbr-login-customiser'), $ip),
                sprintf(/* translators: %s: username */ __('Attempted username: %s', 'mbr-login-customiser'), $username !== '' ? $username : '—'),
                sprintf(/* translators: %s: date/time */ __('Time: %s', 'mbr-login-customiser'), $this->now()),
            )
        );
    }

    /**
     * A user signed in. Alert if they are an administrator on a new IP.
     *
     * @param string  $user_login
     * @param WP_User $user
     */
    public function on_login($user_login, $user = null) {
        if (!$this->enabled() || !get_option('mbr_custom_login_alerts_on_admin_ip', 1)) {
            return;
        }
        if (!($user instanceof WP_User) || !user_can($user, 'manage_options')) {
            return;
        }

        $ip   = MBR_Login_Security::get_client_ip();
        $hash = $this->hash_ip($ip);

        $known = get_user_meta($user->ID, self::KNOWN_IPS_META, true);
        $known = is_array($known) ? $known : array();

        if (in_array($hash, $known, true)) {
            return; // seen before, no alert
        }

        // Record the new IP (newest first, capped).
        array_unshift($known, $hash);
        $known = array_slice($known, 0, self::KNOWN_IPS_MAX);
        update_user_meta($user->ID, self::KNOWN_IPS_META, $known);

        // Don't alert on the very first sign-in we ever record for a user —
        // that would fire for everyone the day the feature is switched on.
        if (count($known) <= 1) {
            return;
        }

        $this->send_alert(
            __('Administrator sign-in from a new IP', 'mbr-login-customiser'),
            array(
                __('An administrator account signed in from an IP address not seen before.', 'mbr-login-customiser'),
                '',
                sprintf(/* translators: %s: username */ __('User: %s', 'mbr-login-customiser'), $user->user_login),
                sprintf(/* translators: %s: IP address */ __('IP address: %s', 'mbr-login-customiser'), $ip),
                sprintf(/* translators: %s: date/time */ __('Time: %s', 'mbr-login-customiser'), $this->now()),
                '',
                __('If this was you, no action is needed. If not, change the password and review active sessions.', 'mbr-login-customiser'),
            )
        );
    }

    /**
     * A failed login. Count them in a rolling window and alert on a spike.
     *
     * @param string $username
     */
    public function on_failed($username) {
        if (!$this->enabled() || !get_option('mbr_custom_login_alerts_on_spike', 1)) {
            return;
        }

        $threshold = max(1, (int) get_option('mbr_custom_login_alerts_spike_threshold', 20));
        $window    = max(1, (int) get_option('mbr_custom_login_alerts_spike_window', 10)) * MINUTE_IN_SECONDS;

        $data = get_transient('mbr_alerts_spike');
        if (!is_array($data) || (time() - (int) ($data['start'] ?? 0)) > $window) {
            $data = array('start' => time(), 'count' => 0);
        }
        $data['count']++;
        set_transient('mbr_alerts_spike', $data, $window);

        if ($data['count'] < $threshold) {
            return;
        }
        if ($this->on_cooldown('spike', 'global')) {
            return;
        }

        $this->send_alert(
            __('Failed-login spike detected', 'mbr-login-customiser'),
            array(
                sprintf(
                    /* translators: 1: number of failed attempts, 2: number of minutes */
                    __('There have been %1$d failed login attempts in the last %2$d minutes.', 'mbr-login-customiser'),
                    (int) $data['count'],
                    (int) round($window / MINUTE_IN_SECONDS)
                ),
                '',
                sprintf(/* translators: %s: IP address */ __('Most recent IP: %s', 'mbr-login-customiser'), MBR_Login_Security::get_client_ip()),
                sprintf(/* translators: %s: username */ __('Most recent username tried: %s', 'mbr-login-customiser'), $username !== '' ? $username : '—'),
                sprintf(/* translators: %s: date/time */ __('Time: %s', 'mbr-login-customiser'), $this->now()),
            )
        );
    }

    /* =====================================================================
     * Delivery
     * ================================================================== */

    /**
     * Send an alert to whichever channels are configured.
     *
     * @param string   $subject Short subject line (site name is prepended).
     * @param string[] $lines   Body lines.
     */
    private function send_alert($subject, array $lines) {
        $site    = wp_specialchars_decode((string) get_bloginfo('name'), ENT_QUOTES);
        $full    = '[' . $site . '] ' . $subject;
        $body    = implode("\n", $lines);

        // Email.
        $to = $this->email_to();
        if ($to) {
            wp_mail($to, $full, $body . "\n\n" . home_url('/'));
        }

        // Webhook (Slack uses "text", Discord uses "content"; sending both keys
        // means each service reads the one it understands and ignores the other).
        $hook = $this->webhook_url();
        if ($hook) {
            $text = $full . "\n" . $body;
            wp_remote_post($hook, array(
                'timeout'  => 5,
                'blocking' => false,
                'headers'  => array('Content-Type' => 'application/json'),
                'body'     => wp_json_encode(array('text' => $text, 'content' => $text)),
            ));
        }

        /**
         * Fires after an alert has been dispatched, for custom integrations.
         *
         * @param string   $subject
         * @param string[] $lines
         */
        do_action('mbr_login_alert_sent', $subject, $lines);
    }

    /**
     * Send a test alert now (used by the settings screen button).
     *
     * @return bool True if at least one channel is configured.
     */
    public function send_test() {
        if (!$this->email_to() && !$this->webhook_url()) {
            return false;
        }
        $this->send_alert(
            __('Test alert', 'mbr-login-customiser'),
            array(
                __('This is a test alert from MBR Login Customiser.', 'mbr-login-customiser'),
                __('If you are reading this, your alert delivery is working.', 'mbr-login-customiser'),
                '',
                sprintf(/* translators: %s: date/time */ __('Time: %s', 'mbr-login-customiser'), $this->now()),
            )
        );
        return true;
    }

    /* =====================================================================
     * Helpers
     * ================================================================== */

    /** True if this alert type/key is still within its cooldown; sets it if not. */
    private function on_cooldown($type, $key) {
        $ck = 'mbr_alert_cd_' . $type . '_' . md5((string) $key);
        if (get_transient($ck)) {
            return true;
        }
        set_transient($ck, 1, $this->cooldown_seconds());
        return false;
    }

    private function hash_ip($ip) {
        return hash_hmac('sha256', (string) $ip, wp_salt('auth'));
    }

    private function now() {
        return wp_date('Y-m-d H:i:s T');
    }

    /* =====================================================================
     * Settings tab
     * ================================================================== */

    public function render_settings_tab() {
        $enabled   = (bool) get_option('mbr_custom_login_alerts_enabled', 0);
        $email     = (string) get_option('mbr_custom_login_alerts_email', '');
        $on_lock   = (bool) get_option('mbr_custom_login_alerts_on_lockout', 1);
        $on_admin  = (bool) get_option('mbr_custom_login_alerts_on_admin_ip', 1);
        $on_spike  = (bool) get_option('mbr_custom_login_alerts_on_spike', 1);
        $threshold = (int) get_option('mbr_custom_login_alerts_spike_threshold', 20);
        $window    = (int) get_option('mbr_custom_login_alerts_spike_window', 10);
        $cooldown  = (int) get_option('mbr_custom_login_alerts_cooldown', 15);
        $webhook   = (string) get_option('mbr_custom_login_alerts_webhook', '');
        ?>
        <form method="post" action="options.php" style="margin-top:1em;">
            <?php settings_fields('mbr_custom_login_alerts'); ?>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><?php esc_html_e('Enable alerts', 'mbr-login-customiser'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="mbr_custom_login_alerts_enabled" value="1" <?php checked($enabled); ?>>
                            <?php esc_html_e('Send a notification when a security event occurs.', 'mbr-login-customiser'); ?>
                        </label>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="mbr_custom_login_alerts_email"><?php esc_html_e('Notification email', 'mbr-login-customiser'); ?></label></th>
                    <td>
                        <input type="email" id="mbr_custom_login_alerts_email" name="mbr_custom_login_alerts_email" value="<?php echo esc_attr($email); ?>" class="regular-text" placeholder="<?php echo esc_attr(get_option('admin_email')); ?>">
                        <p class="description"><?php esc_html_e('Leave blank to use the site administration email.', 'mbr-login-customiser'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="mbr_custom_login_alerts_webhook"><?php esc_html_e('Webhook URL (optional)', 'mbr-login-customiser'); ?></label></th>
                    <td>
                        <input type="url" id="mbr_custom_login_alerts_webhook" name="mbr_custom_login_alerts_webhook" value="<?php echo esc_attr($webhook); ?>" class="regular-text" placeholder="https://hooks.slack.com/…">
                        <p class="description"><?php esc_html_e('Slack or Discord incoming-webhook URL. Alerts are also posted here as a message.', 'mbr-login-customiser'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e('Alert me about', 'mbr-login-customiser'); ?></th>
                    <td>
                        <label style="display:block;margin-bottom:6px;"><input type="checkbox" name="mbr_custom_login_alerts_on_lockout" value="1" <?php checked($on_lock); ?>> <?php esc_html_e('Lockouts (an IP is blocked after repeated failures)', 'mbr-login-customiser'); ?></label>
                        <label style="display:block;margin-bottom:6px;"><input type="checkbox" name="mbr_custom_login_alerts_on_admin_ip" value="1" <?php checked($on_admin); ?>> <?php esc_html_e('Administrator sign-in from a new IP address', 'mbr-login-customiser'); ?></label>
                        <label style="display:block;"><input type="checkbox" name="mbr_custom_login_alerts_on_spike" value="1" <?php checked($on_spike); ?>> <?php esc_html_e('Failed-login spikes', 'mbr-login-customiser'); ?></label>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e('Spike threshold', 'mbr-login-customiser'); ?></th>
                    <td>
                        <?php
                        printf(
                            /* translators: 1: number input for failures, 2: number input for minutes */
                            esc_html__('Alert after %1$s failed attempts within %2$s minutes.', 'mbr-login-customiser'),
                            '<input type="number" min="1" name="mbr_custom_login_alerts_spike_threshold" value="' . esc_attr($threshold) . '" style="width:80px;">',
                            '<input type="number" min="1" name="mbr_custom_login_alerts_spike_window" value="' . esc_attr($window) . '" style="width:80px;">'
                        );
                        ?>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="mbr_custom_login_alerts_cooldown"><?php esc_html_e('Cooldown', 'mbr-login-customiser'); ?></label></th>
                    <td>
                        <input type="number" min="1" id="mbr_custom_login_alerts_cooldown" name="mbr_custom_login_alerts_cooldown" value="<?php echo esc_attr($cooldown); ?>" style="width:80px;"> <?php esc_html_e('minutes', 'mbr-login-customiser'); ?>
                        <p class="description"><?php esc_html_e('Minimum gap between repeat alerts of the same type, so an ongoing attack does not flood you.', 'mbr-login-customiser'); ?></p>
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>

        <?php
        // Test button (separate form, own nonce).
        if (isset($_POST['mbr_alerts_test']) && check_admin_referer('mbr_alerts_test')) {
            $sent = $this->send_test();
            echo '<div class="notice notice-' . ($sent ? 'success' : 'warning') . ' inline"><p>'
                . ($sent
                    ? esc_html__('Test alert sent to the configured channels.', 'mbr-login-customiser')
                    : esc_html__('No delivery channel is configured yet. Save an email or webhook first.', 'mbr-login-customiser'))
                . '</p></div>';
        }
        ?>
        <form method="post" style="margin-top:1em;">
            <?php wp_nonce_field('mbr_alerts_test'); ?>
            <button type="submit" name="mbr_alerts_test" value="1" class="button"><?php esc_html_e('Send a test alert', 'mbr-login-customiser'); ?></button>
        </form>
        <?php
    }
}
