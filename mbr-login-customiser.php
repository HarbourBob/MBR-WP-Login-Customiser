<?php
/**
 * Plugin Name: MBR Login Customiser
 * Plugin URI: https://littlewebshack.com/mbr-login-customiser/
 * Description: Secure your WordPress login by customizing the login URL and appearance with modern design options including Dark Mode and Glassmorphism effects
 * Version: 2.0.0
 * Author:  Robert Palmer
 * Author URI: https://littlewebshack.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: mbr-login-customiser
 * Domain Path: /languages
 */

if (!defined('ABSPATH')) {
    exit;
}

// Buy Me a Coffee
add_filter( 'plugin_row_meta', function ( $links, $file, $data ) {
    if ( ! function_exists( 'plugin_basename' ) || $file !== plugin_basename( __FILE__ ) ) {
        return $links;
    }

    $url = 'https://buymeacoffee.com/robertpalmer/';
    $links[] = sprintf(
	// translators: %s: The name of the plugin author.
        '<a href="%s" target="_blank" rel="noopener nofollow" aria-label="%s">☕ %s</a>',
        esc_url( $url ),
		// translators: %s: The name of the plugin author.
        esc_attr( sprintf( __( 'Buy %s a coffee', 'mbr-login-customiser' ), isset( $data['AuthorName'] ) ? $data['AuthorName'] : __( 'the author', 'mbr-login-customiser' ) ) ),
        esc_html__( 'Buy me a coffee', 'mbr-login-customiser' )
    );

    return $links;
}, 10, 3 );


require_once __DIR__ . '/mbr-updater.php';

mbr_register_updates( array(
    'source' => 'json',
    'url'    => 'https://littlewebshack.com/updates/mbr-login-customiser.json',
    'file'   => __FILE__,
    'slug'   => 'mbr-login-customiser',
) );

define('MBR_CUSTOM_LOGIN_VERSION', '2.0.0');
define('MBR_CUSTOM_LOGIN_PLUGIN_FILE', __FILE__);
define('MBR_CUSTOM_LOGIN_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('MBR_CUSTOM_LOGIN_PLUGIN_URL', plugin_dir_url(__FILE__));

/**
 * Load the plugin modules.
 */
require_once MBR_CUSTOM_LOGIN_PLUGIN_DIR . 'includes/class-mbr-login-options.php';
require_once MBR_CUSTOM_LOGIN_PLUGIN_DIR . 'includes/class-mbr-login-url.php';
require_once MBR_CUSTOM_LOGIN_PLUGIN_DIR . 'includes/class-mbr-login-appearance.php';
require_once MBR_CUSTOM_LOGIN_PLUGIN_DIR . 'includes/class-mbr-login-security.php';
require_once MBR_CUSTOM_LOGIN_PLUGIN_DIR . 'includes/class-mbr-login-access.php';
require_once MBR_CUSTOM_LOGIN_PLUGIN_DIR . 'includes/class-mbr-login-redirect.php';
require_once MBR_CUSTOM_LOGIN_PLUGIN_DIR . 'includes/class-mbr-login-qr.php';
require_once MBR_CUSTOM_LOGIN_PLUGIN_DIR . 'includes/class-mbr-login-2fa.php';
require_once MBR_CUSTOM_LOGIN_PLUGIN_DIR . 'includes/class-mbr-login-passkeys.php';
require_once MBR_CUSTOM_LOGIN_PLUGIN_DIR . 'includes/class-mbr-login-alerts.php';
require_once MBR_CUSTOM_LOGIN_PLUGIN_DIR . 'includes/class-mbr-login-trusted-devices.php';
require_once MBR_CUSTOM_LOGIN_PLUGIN_DIR . 'includes/class-mbr-login-network.php';
require_once MBR_CUSTOM_LOGIN_PLUGIN_DIR . 'includes/class-mbr-login-log.php';
require_once MBR_CUSTOM_LOGIN_PLUGIN_DIR . 'includes/class-mbr-login-admin.php';
require_once MBR_CUSTOM_LOGIN_PLUGIN_DIR . 'includes/class-mbr-login-customiser.php';

/**
 * Boot the plugin.
 */
function mbr_custom_login_init() {
    return MBR_Custom_Login::get_instance();
}
add_action('plugins_loaded', 'mbr_custom_login_init');

/**
 * Activation: seed default options.
 */
register_activation_hook(__FILE__, function() {
    // Login URL defaults
    add_option('mbr_custom_login_slug', 'login');
    add_option('mbr_custom_login_emergency_key', wp_generate_password(32, false));

    // Login limiting defaults (off until the admin enables it)
    add_option('mbr_custom_login_limit_enabled', 0);
    add_option('mbr_custom_login_max_attempts', 5);
    add_option('mbr_custom_login_attempt_window', 15);
    add_option('mbr_custom_login_lockout_duration', 15);
    add_option('mbr_custom_login_progressive_enabled', 1);
    add_option('mbr_custom_login_lockout_multiplier', 2);
    add_option('mbr_custom_login_lockout_max', 1440);
    add_option('mbr_custom_login_offense_memory', 24);
    add_option('mbr_custom_login_behind_proxy', 0);
    add_option('mbr_custom_login_proxy_header', 'HTTP_CF_CONNECTING_IP');
    add_option('mbr_custom_login_whitelist_ips', '');
    add_option('mbr_custom_login_blacklist_ips', '');
    add_option('mbr_custom_login_whitelist_only', 0);

    // Logging defaults (on, 30-day retention).
    add_option('mbr_custom_login_log_enabled', 1);
    add_option('mbr_custom_login_log_retention_days', 30);

    // Redirect defaults (enabled, but a no-op until rules are added).
    add_option('mbr_custom_login_redirect_enabled', 1);
    add_option('mbr_custom_login_redirect_rules', array());
    add_option('mbr_custom_login_redirect_default', '');
    add_option('mbr_custom_login_logout_redirect', '');

    // Schedule defaults (off; all days allowed all-day until configured).
    add_option('mbr_custom_login_time_enabled', 0);
    add_option('mbr_custom_login_2fa_enabled', 0);
    add_option('mbr_custom_login_2fa_app_passwords', 'block');

    // Passkey (WebAuthn) defaults (off; passwordless button mode until changed).
    add_option('mbr_custom_login_passkeys_enabled', 0);
    add_option('mbr_custom_login_passkeys_mode', 'passwordless');

    // Security alert defaults (off until configured).
    add_option('mbr_custom_login_alerts_enabled', 0);
    add_option('mbr_custom_login_alerts_email', '');
    add_option('mbr_custom_login_alerts_webhook', '');
    add_option('mbr_custom_login_alerts_on_lockout', 1);
    add_option('mbr_custom_login_alerts_on_admin_ip', 1);
    add_option('mbr_custom_login_alerts_on_spike', 1);
    add_option('mbr_custom_login_alerts_spike_threshold', 20);
    add_option('mbr_custom_login_alerts_spike_window', 10);
    add_option('mbr_custom_login_alerts_cooldown', 15);

    // Trusted device defaults (off; 30-day trust when enabled).
    add_option('mbr_custom_login_trusted_enabled', 0);
    add_option('mbr_custom_login_trusted_days', 30);
    add_option('mbr_custom_login_time_rules', array(
        0 => array('enabled' => 1, 'start' => '', 'end' => ''),
        1 => array('enabled' => 1, 'start' => '', 'end' => ''),
        2 => array('enabled' => 1, 'start' => '', 'end' => ''),
        3 => array('enabled' => 1, 'start' => '', 'end' => ''),
        4 => array('enabled' => 1, 'start' => '', 'end' => ''),
        5 => array('enabled' => 1, 'start' => '', 'end' => ''),
        6 => array('enabled' => 1, 'start' => '', 'end' => ''),
    ));

    // Create the log table and schedule the daily pruning cron.
    $log = new MBR_Login_Log();
    $log->install();
    if (!wp_next_scheduled(MBR_Login_Log::PRUNE_HOOK)) {
        wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', MBR_Login_Log::PRUNE_HOOK);
    }

    flush_rewrite_rules();
});

/**
 * Deactivation.
 */
register_deactivation_hook(__FILE__, function() {
    // Stop the pruning cron. The log table and its data are left intact so they
    // survive a deactivate/reactivate cycle.
    wp_clear_scheduled_hook(MBR_Login_Log::PRUNE_HOOK);
    flush_rewrite_rules();
});
