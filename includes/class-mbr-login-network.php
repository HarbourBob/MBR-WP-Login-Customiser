<?php
/**
 * Multisite / network support.
 *
 * Adds a Network Admin settings screen for network-wide security policy
 * (a shared IP blacklist, forced 2FA, forced login limiting) and ensures the
 * log table and prune cron are set up for new sites as they join the network.
 *
 * Per-site settings remain per-site; these network options layer on top.
 *
 * @package MBR_Login_Customiser
 */

if (!defined('ABSPATH')) {
    exit;
}

class MBR_Login_Network {

    const PAGE = 'mbr-login-network';

    /**
     * Register WordPress hooks for this module.
     */
    public function register_hooks() {
        add_action('network_admin_menu', array($this, 'add_network_menu'));
        add_action('network_admin_edit_mbr_login_network', array($this, 'save_network_settings'));
        add_action('wp_initialize_site', array($this, 'setup_new_site'), 20, 1);
    }

    /* ---------------------------------------------------------------------
     * New-site setup
     * ------------------------------------------------------------------ */

    /**
     * When a new site is created on the network, create the log table and
     * schedule its prune cron in that site's context.
     *
     * @param WP_Site $new_site
     */
    public function setup_new_site($new_site) {
        if (!is_object($new_site) || empty($new_site->blog_id)) {
            return;
        }
        if (!function_exists('switch_to_blog')) {
            return;
        }
        switch_to_blog((int) $new_site->blog_id);
        if (class_exists('MBR_Login_Log')) {
            $log = new MBR_Login_Log();
            $log->install();
            if (!wp_next_scheduled(MBR_Login_Log::PRUNE_HOOK)) {
                wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', MBR_Login_Log::PRUNE_HOOK);
            }
        }
        restore_current_blog();
    }

    /* ---------------------------------------------------------------------
     * Network admin screen
     * ------------------------------------------------------------------ */

    public function add_network_menu() {
        add_submenu_page(
            'settings.php',
            __('MBR Login Customiser (Network)', 'mbr-login-customiser'),
            __('MBR Login', 'mbr-login-customiser'),
            'manage_network_options',
            self::PAGE,
            array($this, 'render')
        );
    }

    public function render() {
        if (!current_user_can('manage_network_options')) {
            return;
        }
        $blacklist = (string) get_site_option('mbr_custom_login_network_blacklist', '');
        $force_2fa = (bool) get_site_option('mbr_custom_login_network_2fa', 0);
        $force_lock = (bool) get_site_option('mbr_custom_login_network_lockout', 0);
        $updated = isset($_GET['updated']); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        ?>
        <div class="wrap">
            <h1><?php esc_html_e('MBR Login Customiser — Network Settings', 'mbr-login-customiser'); ?></h1>
            <?php if ($updated): ?>
                <div class="notice notice-success is-dismissible"><p><?php esc_html_e('Network settings saved.', 'mbr-login-customiser'); ?></p></div>
            <?php endif; ?>
            <p class="description" style="max-width:720px;">
                <?php esc_html_e('These apply across every site on the network, on top of each site\'s own settings.', 'mbr-login-customiser'); ?>
            </p>
            <form method="post" action="<?php echo esc_url(network_admin_url('edit.php?action=mbr_login_network')); ?>">
                <?php wp_nonce_field('mbr_login_network'); ?>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="mbr_network_blacklist"><?php esc_html_e('Network IP blacklist', 'mbr-login-customiser'); ?></label></th>
                        <td>
                            <textarea id="mbr_network_blacklist" name="mbr_network_blacklist" rows="5" class="large-text code"><?php echo esc_textarea($blacklist); ?></textarea>
                            <p class="description"><?php esc_html_e('One IP or CIDR range per line. These are blocked from signing in on every site in the network.', 'mbr-login-customiser'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Require two-factor', 'mbr-login-customiser'); ?></th>
                        <td><label>
                            <input type="checkbox" name="mbr_network_2fa" value="1" <?php checked($force_2fa); ?>>
                            <?php esc_html_e('Enable two-factor authentication on all sites (users still enrol individually).', 'mbr-login-customiser'); ?>
                        </label></td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Force login limiting', 'mbr-login-customiser'); ?></th>
                        <td><label>
                            <input type="checkbox" name="mbr_network_lockout" value="1" <?php checked($force_lock); ?>>
                            <?php esc_html_e('Turn on failed-login lockouts on all sites.', 'mbr-login-customiser'); ?>
                        </label></td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }

    /**
     * Handle the network settings form submission.
     */
    public function save_network_settings() {
        if (!current_user_can('manage_network_options')) {
            wp_die(esc_html__('You do not have permission to do this.', 'mbr-login-customiser'));
        }
        check_admin_referer('mbr_login_network');

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified above.
        $this->apply_network_settings($_POST);

        wp_safe_redirect(add_query_arg(
            array('page' => self::PAGE, 'updated' => '1'),
            network_admin_url('settings.php')
        ));
        exit;
    }

    /**
     * Persist the network settings from a submitted payload (separated from the
     * redirect so it can be exercised directly).
     *
     * @param array $post
     */
    public function apply_network_settings($post) {
        $blacklist = isset($post['mbr_network_blacklist']) ? wp_unslash($post['mbr_network_blacklist']) : '';
        update_site_option('mbr_custom_login_network_blacklist', self::sanitize_ip_list($blacklist));
        update_site_option('mbr_custom_login_network_2fa', empty($post['mbr_network_2fa']) ? 0 : 1);
        update_site_option('mbr_custom_login_network_lockout', empty($post['mbr_network_lockout']) ? 0 : 1);
    }

    /**
     * Validate a newline-separated list of IPs / CIDR ranges (static so the
     * network handler doesn't depend on the admin module).
     */
    public static function sanitize_ip_list($list) {
        $valid = array();
        $entries = preg_split('/[\r\n]+/', (string) $list);
        foreach ($entries as $entry) {
            $entry = trim($entry);
            if ($entry === '') {
                continue;
            }
            if (strpos($entry, '/') !== false) {
                list($addr, $bits) = array_pad(explode('/', $entry, 2), 2, '');
                if (filter_var($addr, FILTER_VALIDATE_IP) && is_numeric($bits)) {
                    $bits = (int) $bits;
                    $max  = filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 128 : 32;
                    if ($bits >= 0 && $bits <= $max) {
                        $valid[] = $addr . '/' . $bits;
                    }
                }
            } elseif (filter_var($entry, FILTER_VALIDATE_IP)) {
                $valid[] = $entry;
            }
        }
        return implode("\n", array_unique($valid));
    }
}
