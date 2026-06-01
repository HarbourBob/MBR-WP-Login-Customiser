<?php
/**
 * Plugin Name: MBR Login Customiser
 * Plugin URI: https://littlewebshack.com
 * Description: Secure your WordPress login by customizing the login URL and appearance with modern design options including Dark Mode and Glassmorphism effects
 * Version: 1.1.0
 * Author: Made by Robert
 * Author URI: https://littlewebshack.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: mbr-custom-login
 * Domain Path: /languages
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('MBR_CUSTOM_LOGIN_VERSION', '1.1.0');
define('MBR_CUSTOM_LOGIN_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('MBR_CUSTOM_LOGIN_PLUGIN_URL', plugin_dir_url(__FILE__));

/**
 * Main Plugin Class
 */
class MBR_Custom_Login {
    
    private static $instance = null;
    private $login_slug = '';
    private $emergency_key = '';
    
    /**
     * Get singleton instance
     */
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Constructor
     */
    private function __construct() {
        $this->login_slug = get_option('mbr_custom_login_slug', 'login');
        $this->emergency_key = get_option('mbr_custom_login_emergency_key', '');
        
        // Initialize hooks
        add_action('plugins_loaded', array($this, 'init'));
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        
        // Login URL customization hooks
        add_action('init', array($this, 'handle_custom_login_url'));
        add_filter('site_url', array($this, 'filter_site_url'), 10, 4);
        add_filter('wp_redirect', array($this, 'filter_wp_redirect'), 10, 2);
        
        // Block standard login URLs
        add_action('init', array($this, 'block_standard_login'));
        
        // Login page customization
        add_action('login_enqueue_scripts', array($this, 'customize_login_page'));
        add_filter('login_headerurl', array($this, 'custom_login_logo_url'));
        add_filter('login_headertext', array($this, 'custom_login_logo_text'));
        add_filter('login_message', array($this, 'custom_login_message'));
        add_filter('login_footer', array($this, 'custom_login_footer'));

        // Login attempt limiting
        // Priority 99 so we run after WordPress' own authentication callbacks
        // and the lockout decision always wins, even for correct credentials.
        add_filter('authenticate', array($this, 'check_login_lockout'), 99, 3);
        add_action('wp_login_failed', array($this, 'record_failed_login'), 10, 1);
        add_action('wp_login', array($this, 'clear_attempts_on_success'), 10, 2);
    }
    
    /**
     * Initialize plugin
     */
    public function init() {
        load_plugin_textdomain('mbr-custom-login', false, dirname(plugin_basename(__FILE__)) . '/languages');
    }
    
    /**
     * Handle custom login URL requests
     */
    public function handle_custom_login_url() {
        // Check if we're on the custom login URL
        $request_uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $request_uri = rtrim($request_uri, '/');
        $home_path = trim(parse_url(home_url(), PHP_URL_PATH), '/');
        
        // Remove home path from request URI
        if ($home_path && strpos($request_uri, $home_path) === 0) {
            $request_uri = substr($request_uri, strlen($home_path));
        }
        $request_uri = ltrim($request_uri, '/');
        
        // Check for emergency access
        if (isset($_GET['mbr_emergency']) && !empty($this->emergency_key)) {
            if ($_GET['mbr_emergency'] === $this->emergency_key) {
                $this->redirect_to_login();
                exit;
            }
        }
        
        // Check if this is our custom login URL
        if ($request_uri === $this->login_slug || $request_uri === $this->login_slug . '/') {
            $this->redirect_to_login();
            exit;
        }
    }
    
    /**
     * Redirect to actual login page
     */
    private function redirect_to_login() {
        // Preserve query parameters
        $query_string = $_SERVER['QUERY_STRING'];
        parse_str($query_string, $query_params);
        
        // Remove our emergency key from params
        unset($query_params['mbr_emergency']);
        
        // Build the actual login URL
        $login_url = site_url('wp-login.php');
        
        if (!empty($query_params)) {
            $login_url = add_query_arg($query_params, $login_url);
        }
        
        // Set a cookie/transient to allow this session through
        $token = wp_generate_password(32, false);
        set_transient('mbr_login_allowed_' . $token, true, 300); // 5 minutes
        setcookie('mbr_login_token', $token, time() + 300, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
        
        require_once ABSPATH . 'wp-login.php';
        exit;
    }
    
    /**
     * Block access to standard login URLs
     */
    public function block_standard_login() {
        global $pagenow;
        
        // Allow if user is already logged in
        if (is_user_logged_in()) {
            return;
        }
        
        // Check for valid token
        if (isset($_COOKIE['mbr_login_token'])) {
            $token = sanitize_text_field($_COOKIE['mbr_login_token']);
            if (get_transient('mbr_login_allowed_' . $token)) {
                return;
            }
        }
        
        // Check if accessing standard login pages
        if ($pagenow === 'wp-login.php' || $pagenow === 'wp-signup.php') {
            $this->show_404();
        }
        
        // Block direct access to wp-admin when not logged in
        if (is_admin() && !wp_doing_ajax()) {
            $this->show_404();
        }
    }
    
    /**
     * Show 404 error
     */
    private function show_404() {
        global $wp_query;
        $wp_query->set_404();
        status_header(404);
        
        // Try to load theme's 404 template
        if (file_exists(get_template_directory() . '/404.php')) {
            include(get_template_directory() . '/404.php');
        } else {
            wp_die(__('Page not found', 'mbr-custom-login'), '404 - Not Found', array('response' => 404));
        }
        exit;
    }
    
    /**
     * Filter site URL to replace wp-login.php with custom slug
     */
    public function filter_site_url($url, $path, $scheme, $blog_id) {
        if (strpos($url, 'wp-login.php') !== false && !is_admin()) {
            $url = str_replace('wp-login.php', $this->login_slug, $url);
        }
        return $url;
    }
    
    /**
     * Filter redirects to use custom login URL
     */
    public function filter_wp_redirect($location, $status) {
        if (strpos($location, 'wp-login.php') !== false) {
            $location = str_replace('wp-login.php', $this->login_slug, $location);
        }
        return $location;
    }
    
    /**
     * Customize login page appearance
     */
    public function customize_login_page() {
        $custom_logo = get_option('mbr_custom_login_logo', '');
        $bg_type = get_option('mbr_custom_login_bg_type', 'color');
        $custom_bg_color = get_option('mbr_custom_login_bg_color', '#f0f0f1');
        $custom_bg_gradient_start = get_option('mbr_custom_login_bg_gradient_start', '#667eea');
        $custom_bg_gradient_end = get_option('mbr_custom_login_bg_gradient_end', '#764ba2');
        $custom_bg_gradient_direction = get_option('mbr_custom_login_bg_gradient_direction', 'to bottom right');
        $custom_bg_image = get_option('mbr_custom_login_bg_image', '');
        $form_style = get_option('mbr_custom_login_form_style', 'default');
        $custom_button_color = get_option('mbr_custom_login_button_color', '#2271b1');
        $font_family = get_option('mbr_custom_login_font_family', 'default');
        $animation = get_option('mbr_custom_login_animation', 'none');
        $box_shadow = get_option('mbr_custom_login_box_shadow', 'medium');
        $custom_css = get_option('mbr_custom_login_css', '');
        
        // Google Fonts URL if custom font selected
        $google_fonts_url = '';
        if ($font_family !== 'default' && $font_family !== 'system') {
            $font_name = str_replace('+', ' ', $font_family);
            $google_fonts_url = 'https://fonts.googleapis.com/css2?family=' . $font_family . ':wght@400;500;600;700&display=swap';
        }
        
        ?>
        <?php if (!empty($google_fonts_url)): ?>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="<?php echo esc_url($google_fonts_url); ?>" rel="stylesheet">
        <?php endif; ?>
        <style type="text/css">
            body.login {
                <?php if ($bg_type === 'color'): ?>
                    background-color: <?php echo esc_attr($custom_bg_color); ?>;
                <?php elseif ($bg_type === 'gradient'): ?>
                    background: linear-gradient(<?php echo esc_attr($custom_bg_gradient_direction); ?>, <?php echo esc_attr($custom_bg_gradient_start); ?>, <?php echo esc_attr($custom_bg_gradient_end); ?>);
                    background-attachment: fixed;
                <?php elseif ($bg_type === 'image' && !empty($custom_bg_image)): ?>
                    background-image: url('<?php echo esc_url($custom_bg_image); ?>');
                    background-size: cover;
                    background-position: center;
                    background-repeat: no-repeat;
                    background-attachment: fixed;
                <?php endif; ?>
            }
            
            <?php if (!empty($custom_logo)): ?>
            #login h1 a {
                background-image: url('<?php echo esc_url($custom_logo); ?>');
                background-size: contain;
                width: 100%;
                height: 100px;
            }
            <?php endif; ?>
            
            <?php if ($font_family !== 'default'): ?>
            body.login,
            body.login form,
            body.login label,
            body.login input,
            body.login .message,
            body.login #backtoblog a,
            body.login #nav a {
                <?php if ($font_family === 'system'): ?>
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif !important;
                <?php else: ?>
                    font-family: '<?php echo str_replace('+', ' ', esc_attr($font_family)); ?>', sans-serif !important;
                <?php endif; ?>
            }
            <?php endif; ?>
            
            <?php if ($animation !== 'none'): ?>
            /* Animation Styles */
            @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }
            
            @keyframes slideDown {
                from {
                    opacity: 0;
                    transform: translateY(-30px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            @keyframes zoomIn {
                from {
                    opacity: 0;
                    transform: scale(0.9);
                }
                to {
                    opacity: 1;
                    transform: scale(1);
                }
            }
            
            @keyframes bounce {
                0% {
                    opacity: 0;
                    transform: translateY(-50px);
                }
                60% {
                    opacity: 1;
                    transform: translateY(10px);
                }
                80% {
                    transform: translateY(-5px);
                }
                100% {
                    transform: translateY(0);
                }
            }
            
            #login {
                <?php if ($animation === 'fade'): ?>
                    animation: fadeIn 0.6s ease-out;
                <?php elseif ($animation === 'slide'): ?>
                    animation: slideDown 0.5s ease-out;
                <?php elseif ($animation === 'zoom'): ?>
                    animation: zoomIn 0.5s ease-out;
                <?php elseif ($animation === 'bounce'): ?>
                    animation: bounce 0.8s ease-out;
                <?php endif; ?>
            }
            <?php endif; ?>
            
            /* Box Shadow Styles */
            <?php
            $shadow_value = '';
            switch ($box_shadow) {
                case 'none':
                    $shadow_value = 'none';
                    break;
                case 'subtle':
                    $shadow_value = '0 2px 8px rgba(0, 0, 0, 0.1)';
                    break;
                case 'medium':
                    $shadow_value = '0 4px 16px rgba(0, 0, 0, 0.15)';
                    break;
                case 'strong':
                    $shadow_value = '0 8px 32px rgba(0, 0, 0, 0.25)';
                    break;
                case 'glow':
                    $shadow_value = '0 0 40px rgba(' . $this->hex_to_rgb($custom_button_color) . ', 0.3)';
                    break;
            }
            ?>
            
            body.login div#login form#loginform,
            body.login div#login form#lostpasswordform,
            body.login div#login form#registerform {
                box-shadow: <?php echo $shadow_value; ?> !important;
            }
            
            <?php if ($form_style === 'dark'): ?>
            /* Dark Mode Styling */
            body.login div#login form#loginform,
            body.login div#login form#lostpasswordform,
            body.login div#login form#registerform {
                background: rgba(30, 30, 30, 0.95) !important;
                border: 1px solid rgba(255, 255, 255, 0.1) !important;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4) !important;
            }
            
            body.login div#login form .input,
            body.login div#login form input[type="text"],
            body.login div#login form input[type="password"],
            body.login div#login form input[type="email"],
            body.login div#login input[type="text"],
            body.login div#login input[type="password"],
            body.login div#login input[type="email"] {
                background: rgba(50, 50, 50, 0.8) !important;
                border: 1px solid rgba(255, 255, 255, 0.2) !important;
                color: #ffffff !important;
                box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.3) !important;
            }
            
            body.login div#login form .input::placeholder,
            body.login div#login form input[type="text"]::placeholder,
            body.login div#login form input[type="password"]::placeholder,
            body.login div#login form input[type="email"]::placeholder {
                color: rgba(255, 255, 255, 0.5) !important;
            }
            
            body.login div#login form .input:focus,
            body.login div#login form input[type="text"]:focus,
            body.login div#login form input[type="password"]:focus,
            body.login div#login form input[type="email"]:focus {
                background: rgba(60, 60, 60, 0.9) !important;
                border-color: <?php echo esc_attr($custom_button_color); ?> !important;
                color: #ffffff !important;
                box-shadow: 0 0 0 1px <?php echo esc_attr($custom_button_color); ?> !important;
            }
            
            body.login div#login form label,
            body.login div#login label {
                color: rgba(255, 255, 255, 0.9) !important;
            }
            
            body.login #backtoblog a,
            body.login #nav a {
                color: rgba(255, 255, 255, 0.7) !important;
            }
            
            body.login #backtoblog a:hover,
            body.login #nav a:hover {
                color: rgba(255, 255, 255, 0.9) !important;
            }
            
            body.login .message,
            body.login .success,
            body.login #login_error {
                background: rgba(50, 50, 50, 0.9) !important;
                border-left-color: <?php echo esc_attr($custom_button_color); ?> !important;
                color: #ffffff !important;
            }
            
            body.login #login_error {
                border-left-color: #dc3232 !important;
            }
            
            body.login .button.wp-hide-pw {
                background: transparent !important;
                border: none !important;
                color: rgba(255, 255, 255, 0.7) !important;
            }
            
            body.login .button.wp-hide-pw:hover {
                color: rgba(255, 255, 255, 0.9) !important;
            }
            
            body.login .button.wp-hide-pw .dashicons {
                color: rgba(255, 255, 255, 0.7) !important;
            }
            
            <?php elseif ($form_style === 'glass'): ?>
            /* Glassmorphism Styling */
            .login form {
                background: rgba(255, 255, 255, 0.15) !important;
                backdrop-filter: blur(12px) !important;
                -webkit-backdrop-filter: blur(12px) !important;
                border: 1px solid rgba(255, 255, 255, 0.25) !important;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2) !important;
            }
            
            .login form .input,
            .login input[type="text"],
            .login input[type="password"],
            .login input[type="email"] {
                background: rgba(255, 255, 255, 0.25) !important;
                backdrop-filter: blur(5px) !important;
                -webkit-backdrop-filter: blur(5px) !important;
                border: 1px solid rgba(255, 255, 255, 0.35) !important;
                color: #1a1a1a !important;
                box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.1) !important;
            }
            
            .login form .input::placeholder,
            .login input[type="text"]::placeholder,
            .login input[type="password"]::placeholder,
            .login input[type="email"]::placeholder {
                color: rgba(0, 0, 0, 0.5) !important;
            }
            
            .login form .input:focus,
            .login input[type="text"]:focus,
            .login input[type="password"]:focus,
            .login input[type="email"]:focus {
                background: rgba(255, 255, 255, 0.35) !important;
                border-color: rgba(255, 255, 255, 0.55) !important;
                color: #1a1a1a !important;
                box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.5) !important;
            }
            
            .login label {
                color: rgba(0, 0, 0, 0.85) !important;
                text-shadow: 0 1px 2px rgba(255, 255, 255, 0.4);
                font-weight: 500;
            }
            
            .login #backtoblog a,
            .login #nav a {
                color: rgba(0, 0, 0, 0.75) !important;
                text-shadow: 0 1px 2px rgba(255, 255, 255, 0.4);
            }
            
            .login #backtoblog a:hover,
            .login #nav a:hover {
                color: rgba(0, 0, 0, 0.95) !important;
            }
            
            .login .message,
            .login .success {
                background: rgba(255, 255, 255, 0.25) !important;
                backdrop-filter: blur(12px) !important;
                -webkit-backdrop-filter: blur(12px) !important;
                border: 1px solid rgba(255, 255, 255, 0.35) !important;
                border-left-width: 4px !important;
                border-left-color: <?php echo esc_attr($custom_button_color); ?> !important;
                color: rgba(0, 0, 0, 0.9) !important;
            }
            
            .login #login_error {
                background: rgba(255, 220, 220, 0.35) !important;
                backdrop-filter: blur(12px) !important;
                -webkit-backdrop-filter: blur(12px) !important;
                border: 1px solid rgba(255, 100, 100, 0.35) !important;
                border-left-width: 4px !important;
                border-left-color: #dc3232 !important;
                color: rgba(0, 0, 0, 0.9) !important;
            }
            
            .login .button.wp-hide-pw {
                background: transparent !important;
                border: none !important;
                color: rgba(0, 0, 0, 0.6) !important;
            }
            
            .login .button.wp-hide-pw:hover {
                color: rgba(0, 0, 0, 0.85) !important;
            }
            <?php endif; ?>
            
            /* Button color - applies to all styles */
            .wp-core-ui .button-primary {
                background: <?php echo esc_attr($custom_button_color); ?> !important;
                border-color: <?php echo esc_attr($custom_button_color); ?> !important;
                box-shadow: none !important;
                text-shadow: none !important;
            }
            
            .wp-core-ui .button-primary:hover,
            .wp-core-ui .button-primary:focus {
                background: <?php echo esc_attr($this->adjust_brightness($custom_button_color, -20)); ?> !important;
                border-color: <?php echo esc_attr($this->adjust_brightness($custom_button_color, -30)); ?> !important;
            }
            
            .wp-core-ui .button-primary:active {
                background: <?php echo esc_attr($this->adjust_brightness($custom_button_color, -30)); ?> !important;
                border-color: <?php echo esc_attr($this->adjust_brightness($custom_button_color, -40)); ?> !important;
            }
            
            <?php echo wp_strip_all_tags($custom_css); ?>
        </style>
        <?php
    }
    
    /**
     * Adjust color brightness
     */
    private function adjust_brightness($hex, $steps) {
        $hex = str_replace('#', '', $hex);
        $r = hexdec(substr($hex, 0, 2));
        $g = hexdec(substr($hex, 2, 2));
        $b = hexdec(substr($hex, 4, 2));
        
        $r = max(0, min(255, $r + $steps));
        $g = max(0, min(255, $g + $steps));
        $b = max(0, min(255, $b + $steps));
        
        return '#' . str_pad(dechex($r), 2, '0', STR_PAD_LEFT)
                  . str_pad(dechex($g), 2, '0', STR_PAD_LEFT)
                  . str_pad(dechex($b), 2, '0', STR_PAD_LEFT);
    }
    
    /**
     * Convert hex color to RGB values
     */
    private function hex_to_rgb($hex) {
        $hex = str_replace('#', '', $hex);
        $r = hexdec(substr($hex, 0, 2));
        $g = hexdec(substr($hex, 2, 2));
        $b = hexdec(substr($hex, 4, 2));
        return "$r, $g, $b";
    }
    
    /**
     * Custom login logo URL
     */
    public function custom_login_logo_url($url) {
        $custom_url = get_option('mbr_custom_login_logo_url', home_url());
        return $custom_url ?: $url;
    }
    
    /**
     * Custom login logo text
     */
    public function custom_login_logo_text($text) {
        $custom_text = get_option('mbr_custom_login_logo_text', get_bloginfo('name'));
        return $custom_text ?: $text;
    }
    
    /**
     * Custom login message
     */
    public function custom_login_message($message) {
        $custom_message = get_option('mbr_custom_login_message', '');
        if (!empty($custom_message)) {
            $message .= '<p class="message">' . wp_kses_post($custom_message) . '</p>';
        }
        return $message;
    }
    
    /**
     * Custom login footer
     */
    public function custom_login_footer() {
        $footer_text = get_option('mbr_custom_login_footer_text', '');
        if (!empty($footer_text)) {
            echo '<div class="mbr-custom-footer" style="text-align: center; padding: 20px 0; margin-top: 20px;">';
            echo wp_kses_post($footer_text);
            echo '</div>';
        }
    }
    
    /* -------------------------------------------------------------------------
     * Login attempt limiting
     * ---------------------------------------------------------------------- */

    /**
     * Option key holding per-IP attempt/lockout data.
     */
    const ATTEMPT_OPTION = 'mbr_custom_login_attempt_data';

    /**
     * Get the visitor's IP address.
     *
     * Defaults to REMOTE_ADDR. If the site is flagged as being behind a
     * proxy/CDN, trust the first valid public IP from the relevant header.
     * Spoofable headers are only consulted when the admin opts in.
     */
    private function get_client_ip() {
        $behind_proxy = get_option('mbr_custom_login_behind_proxy', 0);

        if ($behind_proxy) {
            $headers = array(
                'HTTP_CF_CONNECTING_IP', // Cloudflare
                'HTTP_TRUE_CLIENT_IP',   // Akamai / Cloudflare Enterprise
                'HTTP_X_FORWARDED_FOR',  // Generic proxies (may be a list)
                'HTTP_X_REAL_IP',
            );

            foreach ($headers as $header) {
                if (empty($_SERVER[$header])) {
                    continue;
                }

                // X-Forwarded-For can be "client, proxy1, proxy2".
                $parts = explode(',', wp_unslash($_SERVER[$header]));
                foreach ($parts as $candidate) {
                    $candidate = trim($candidate);
                    if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                        return $candidate;
                    }
                }
            }
        }

        $remote = isset($_SERVER['REMOTE_ADDR']) ? wp_unslash($_SERVER['REMOTE_ADDR']) : '';
        return filter_var($remote, FILTER_VALIDATE_IP) ? $remote : '0.0.0.0';
    }

    /**
     * Storage key for an IP (hashed to avoid storing raw IPs as array keys).
     */
    private function ip_key($ip) {
        return md5($ip);
    }

    /**
     * Is the given IP exempt from limiting (whitelisted)?
     */
    private function is_ip_whitelisted($ip) {
        $list = get_option('mbr_custom_login_whitelist_ips', '');
        if (empty($list)) {
            return false;
        }

        $entries = preg_split('/[\r\n]+/', $list);
        foreach ($entries as $entry) {
            $entry = trim($entry);
            if ($entry !== '' && $entry === $ip) {
                return true;
            }
        }
        return false;
    }

    /**
     * Read the attempt data option (and prune fully-expired entries).
     */
    private function get_attempt_data() {
        $data = get_option(self::ATTEMPT_OPTION, array());
        if (!is_array($data)) {
            $data = array();
        }

        $now = time();
        $changed = false;
        foreach ($data as $key => $rec) {
            $window_done = empty($rec['window_expires']) || $rec['window_expires'] < $now;
            $lock_done   = empty($rec['lock_until']) || $rec['lock_until'] < $now;
            if ($window_done && $lock_done) {
                unset($data[$key]);
                $changed = true;
            }
        }

        if ($changed) {
            update_option(self::ATTEMPT_OPTION, $data, false);
        }
        return $data;
    }

    /**
     * Persist the attempt data option (never autoloaded).
     */
    private function save_attempt_data($data) {
        update_option(self::ATTEMPT_OPTION, $data, false);
    }

    /**
     * Block authentication while an IP is locked out.
     *
     * Runs late (priority 99) so it overrides a valid WP_User result too:
     * once locked, even correct credentials are refused until the timer ends.
     */
    public function check_login_lockout($user, $username, $password) {
        // Nothing to do if no credentials were submitted (e.g. cookie auth).
        if (empty($username) && empty($password)) {
            return $user;
        }

        if (!get_option('mbr_custom_login_limit_enabled', 0)) {
            return $user;
        }

        $ip = $this->get_client_ip();
        if ($this->is_ip_whitelisted($ip)) {
            return $user;
        }

        $data = $this->get_attempt_data();
        $key  = $this->ip_key($ip);

        if (!empty($data[$key]['lock_until']) && $data[$key]['lock_until'] > time()) {
            $remaining = $data[$key]['lock_until'] - time();
            $minutes   = max(1, (int) ceil($remaining / 60));

            return new WP_Error(
                'mbr_login_locked',
                sprintf(
                    /* translators: %d: number of minutes remaining */
                    _n(
                        '<strong>Too many failed attempts.</strong> Please try again in %d minute.',
                        '<strong>Too many failed attempts.</strong> Please try again in %d minutes.',
                        $minutes,
                        'mbr-custom-login'
                    ),
                    $minutes
                )
            );
        }

        return $user;
    }

    /**
     * Record a failed login and lock the IP once the limit is reached.
     */
    public function record_failed_login($username) {
        if (!get_option('mbr_custom_login_limit_enabled', 0)) {
            return;
        }

        $ip = $this->get_client_ip();
        if ($this->is_ip_whitelisted($ip)) {
            return;
        }

        $max          = max(1, (int) get_option('mbr_custom_login_max_attempts', 5));
        $window_mins  = max(1, (int) get_option('mbr_custom_login_attempt_window', 15));
        $lockout_mins = max(1, (int) get_option('mbr_custom_login_lockout_duration', 15));

        $data = $this->get_attempt_data();
        $key  = $this->ip_key($ip);
        $now  = time();

        // Already locked: don't extend the lockout on every blocked attempt.
        if (!empty($data[$key]['lock_until']) && $data[$key]['lock_until'] > $now) {
            return;
        }

        // Reset the counter if the rolling window has expired.
        if (empty($data[$key]) || empty($data[$key]['window_expires']) || $data[$key]['window_expires'] < $now) {
            $data[$key] = array(
                'fails'          => 0,
                'window_expires' => $now + ($window_mins * MINUTE_IN_SECONDS),
                'lock_until'     => 0,
            );
        }

        $data[$key]['fails']++;
        $data[$key]['ip']   = $ip;
        $data[$key]['last'] = $now;

        if ($data[$key]['fails'] >= $max) {
            $data[$key]['lock_until'] = $now + ($lockout_mins * MINUTE_IN_SECONDS);
            $data[$key]['fails']      = 0; // reset so the next window starts fresh
        }

        $this->save_attempt_data($data);
    }

    /**
     * Clear an IP's record after a successful login.
     */
    public function clear_attempts_on_success($user_login, $user = null) {
        $ip   = $this->get_client_ip();
        $data = $this->get_attempt_data();
        $key  = $this->ip_key($ip);

        if (isset($data[$key])) {
            unset($data[$key]);
            $this->save_attempt_data($data);
        }
    }

    /**
     * Add admin menu
     */
    public function add_admin_menu() {
        $page_hook = add_options_page(
            __('MBR Login Customiser', 'mbr-custom-login'),
            __('Login Customiser', 'mbr-custom-login'),
            'manage_options',
            'mbr-custom-login',
            array($this, 'render_settings_page')
        );
        
        // Enqueue media uploader and color picker on our settings page
        add_action('load-' . $page_hook, array($this, 'load_admin_scripts'));
    }
    
    /**
     * Load admin scripts
     */
    public function load_admin_scripts() {
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
    }
    
    /**
     * Enqueue admin scripts and styles
     */
    public function enqueue_admin_scripts() {
        // Enqueue WordPress media uploader
        wp_enqueue_media();
        
        // Enqueue color picker
        wp_enqueue_style('wp-color-picker');
        wp_enqueue_script('wp-color-picker');
        
        // Enqueue custom admin script
        wp_enqueue_script(
            'mbr-custom-login-admin',
            plugin_dir_url(__FILE__) . 'admin.js',
            array('jquery', 'wp-color-picker'),
            MBR_CUSTOM_LOGIN_VERSION,
            true
        );
    }
    
    /**
     * Register plugin settings
     */
    public function register_settings() {
        // URL Settings
        register_setting('mbr_custom_login_url', 'mbr_custom_login_slug', array(
            'sanitize_callback' => array($this, 'sanitize_slug')
        ));
        register_setting('mbr_custom_login_url', 'mbr_custom_login_emergency_key', array(
            'sanitize_callback' => 'sanitize_text_field'
        ));
        
        // Appearance Settings
        register_setting('mbr_custom_login_appearance', 'mbr_custom_login_logo', 'esc_url_raw');
        register_setting('mbr_custom_login_appearance', 'mbr_custom_login_logo_url', 'esc_url_raw');
        register_setting('mbr_custom_login_appearance', 'mbr_custom_login_logo_text', 'sanitize_text_field');
        register_setting('mbr_custom_login_appearance', 'mbr_custom_login_message', 'wp_kses_post');
        register_setting('mbr_custom_login_appearance', 'mbr_custom_login_bg_type', array(
            'sanitize_callback' => array($this, 'sanitize_bg_type')
        ));
        register_setting('mbr_custom_login_appearance', 'mbr_custom_login_bg_color', 'sanitize_hex_color');
        register_setting('mbr_custom_login_appearance', 'mbr_custom_login_bg_gradient_start', 'sanitize_hex_color');
        register_setting('mbr_custom_login_appearance', 'mbr_custom_login_bg_gradient_end', 'sanitize_hex_color');
        register_setting('mbr_custom_login_appearance', 'mbr_custom_login_bg_gradient_direction', 'sanitize_text_field');
        register_setting('mbr_custom_login_appearance', 'mbr_custom_login_bg_image', 'esc_url_raw');
        register_setting('mbr_custom_login_appearance', 'mbr_custom_login_form_style', array(
            'sanitize_callback' => array($this, 'sanitize_form_style')
        ));
        register_setting('mbr_custom_login_appearance', 'mbr_custom_login_button_color', 'sanitize_hex_color');
        register_setting('mbr_custom_login_appearance', 'mbr_custom_login_font_family', 'sanitize_text_field');
        register_setting('mbr_custom_login_appearance', 'mbr_custom_login_animation', array(
            'sanitize_callback' => array($this, 'sanitize_animation')
        ));
        register_setting('mbr_custom_login_appearance', 'mbr_custom_login_box_shadow', array(
            'sanitize_callback' => array($this, 'sanitize_box_shadow')
        ));
        register_setting('mbr_custom_login_appearance', 'mbr_custom_login_footer_text', 'wp_kses_post');
        register_setting('mbr_custom_login_appearance', 'mbr_custom_login_css', array(
            'sanitize_callback' => array($this, 'sanitize_css')
        ));

        // Security / Login Attempt Settings
        register_setting('mbr_custom_login_security', 'mbr_custom_login_limit_enabled', array(
            'sanitize_callback' => array($this, 'sanitize_checkbox')
        ));
        register_setting('mbr_custom_login_security', 'mbr_custom_login_max_attempts', array(
            'sanitize_callback' => 'absint'
        ));
        register_setting('mbr_custom_login_security', 'mbr_custom_login_attempt_window', array(
            'sanitize_callback' => 'absint'
        ));
        register_setting('mbr_custom_login_security', 'mbr_custom_login_lockout_duration', array(
            'sanitize_callback' => 'absint'
        ));
        register_setting('mbr_custom_login_security', 'mbr_custom_login_behind_proxy', array(
            'sanitize_callback' => array($this, 'sanitize_checkbox')
        ));
        register_setting('mbr_custom_login_security', 'mbr_custom_login_whitelist_ips', array(
            'sanitize_callback' => array($this, 'sanitize_ip_list')
        ));
    }

    /**
     * Sanitize a checkbox value to 0/1.
     */
    public function sanitize_checkbox($value) {
        return !empty($value) ? 1 : 0;
    }

    /**
     * Sanitize a newline-separated IP whitelist, keeping only valid IPs.
     */
    public function sanitize_ip_list($list) {
        $valid = array();
        $entries = preg_split('/[\r\n]+/', (string) $list);
        foreach ($entries as $entry) {
            $entry = trim($entry);
            if ($entry !== '' && filter_var($entry, FILTER_VALIDATE_IP)) {
                $valid[] = $entry;
            }
        }
        return implode("\n", array_unique($valid));
    }
    
    /**
     * Sanitize animation type
     */
    public function sanitize_animation($animation) {
        $allowed = array('none', 'fade', 'slide', 'zoom', 'bounce');
        return in_array($animation, $allowed) ? $animation : 'none';
    }
    
    /**
     * Sanitize box shadow
     */
    public function sanitize_box_shadow($shadow) {
        $allowed = array('none', 'subtle', 'medium', 'strong', 'glow');
        return in_array($shadow, $allowed) ? $shadow : 'medium';
    }
    
    /**
     * Sanitize form style
     */
    public function sanitize_form_style($style) {
        $allowed = array('default', 'dark', 'glass');
        return in_array($style, $allowed) ? $style : 'default';
    }
    
    /**
     * Sanitize background type
     */
    public function sanitize_bg_type($type) {
        $allowed = array('color', 'gradient', 'image');
        return in_array($type, $allowed) ? $type : 'color';
    }
    
    /**
     * Sanitize slug
     */
    public function sanitize_slug($slug) {
        $slug = sanitize_title($slug);
        
        // Prevent using reserved slugs
        $reserved = array('wp-admin', 'wp-login', 'login', 'admin', 'wp-includes', 'wp-content');
        if (in_array($slug, $reserved)) {
            add_settings_error(
                'mbr_custom_login_slug',
                'reserved_slug',
                __('This slug is reserved. Please choose another.', 'mbr-custom-login')
            );
            return get_option('mbr_custom_login_slug', 'login');
        }
        
        return $slug;
    }
    
    /**
     * Sanitize custom CSS
     */
    public function sanitize_css($css) {
        // Strip tags but allow CSS
        return wp_strip_all_tags($css);
    }
    
    /**
     * Render settings page
     */
    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        // Get current tab
        $active_tab = isset($_GET['tab']) ? sanitize_text_field($_GET['tab']) : 'url';

        // Handle a manual unlock request (single IP or all).
        if ($active_tab === 'security' && isset($_GET['mbr_unlock']) && isset($_GET['_wpnonce'])) {
            if (wp_verify_nonce(sanitize_text_field($_GET['_wpnonce']), 'mbr_unlock')) {
                $target = sanitize_text_field($_GET['mbr_unlock']);
                if ($target === 'all') {
                    $this->save_attempt_data(array());
                } else {
                    $data = $this->get_attempt_data();
                    if (isset($data[$target])) {
                        unset($data[$target]);
                        $this->save_attempt_data($data);
                    }
                }
                echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Lockout(s) cleared.', 'mbr-custom-login') . '</p></div>';
            }
        }
        
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            
            <h2 class="nav-tab-wrapper">
                <a href="?page=mbr-custom-login&tab=url" class="nav-tab <?php echo $active_tab === 'url' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Login URL', 'mbr-custom-login'); ?>
                </a>
                <a href="?page=mbr-custom-login&tab=appearance" class="nav-tab <?php echo $active_tab === 'appearance' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Appearance', 'mbr-custom-login'); ?>
                </a>
                <a href="?page=mbr-custom-login&tab=security" class="nav-tab <?php echo $active_tab === 'security' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Security', 'mbr-custom-login'); ?>
                </a>
            </h2>
            
            <?php settings_errors(); ?>
            
            <?php if ($active_tab === 'url'): ?>
                <form method="post" action="options.php">
                    <?php settings_fields('mbr_custom_login_url'); ?>
                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_slug">
                                    <?php _e('Custom Login Slug', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="text" 
                                       id="mbr_custom_login_slug" 
                                       name="mbr_custom_login_slug" 
                                       value="<?php echo esc_attr($this->login_slug); ?>" 
                                       class="regular-text">
                                <p class="description">
                                    <?php 
                                    printf(
                                        __('Your login page will be: %s', 'mbr-custom-login'),
                                        '<code>' . esc_html(home_url($this->login_slug)) . '</code>'
                                    );
                                    ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_emergency_key">
                                    <?php _e('Emergency Access Key', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="text" 
                                       id="mbr_custom_login_emergency_key" 
                                       name="mbr_custom_login_emergency_key" 
                                       value="<?php echo esc_attr($this->emergency_key); ?>" 
                                       class="regular-text">
                                <p class="description">
                                    <?php _e('If you forget your login URL, you can access it using:', 'mbr-custom-login'); ?>
                                    <br>
                                    <code><?php echo esc_html(home_url('?mbr_emergency=' . $this->emergency_key)); ?></code>
                                </p>
                                <button type="button" class="button" onclick="document.getElementById('mbr_custom_login_emergency_key').value = '<?php echo wp_generate_password(32, false); ?>';">
                                    <?php _e('Generate New Key', 'mbr-custom-login'); ?>
                                </button>
                            </td>
                        </tr>
                    </table>
                    <?php submit_button(); ?>
                </form>
            <?php elseif ($active_tab === 'appearance'): ?>
                <form method="post" action="options.php">
                    <?php settings_fields('mbr_custom_login_appearance'); ?>
                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_logo">
                                    <?php _e('Custom Logo', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="hidden" 
                                       id="mbr_custom_login_logo" 
                                       name="mbr_custom_login_logo" 
                                       value="<?php echo esc_attr(get_option('mbr_custom_login_logo', '')); ?>">
                                <div id="logo-preview" style="margin-bottom: 10px;">
                                    <?php 
                                    $logo_url = get_option('mbr_custom_login_logo', '');
                                    if (!empty($logo_url)): 
                                    ?>
                                        <img src="<?php echo esc_url($logo_url); ?>" style="max-width: 320px; max-height: 100px; display: block; margin-bottom: 10px;">
                                    <?php endif; ?>
                                </div>
                                <button type="button" class="button" id="upload_logo_button">
                                    <?php _e('Choose Logo', 'mbr-custom-login'); ?>
                                </button>
                                <button type="button" class="button" id="remove_logo_button" <?php echo empty($logo_url) ? 'style="display:none;"' : ''; ?>>
                                    <?php _e('Remove Logo', 'mbr-custom-login'); ?>
                                </button>
                                <p class="description">
                                    <?php _e('Recommended size: 320x80 pixels', 'mbr-custom-login'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_logo_url">
                                    <?php _e('Logo Link URL', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="url" 
                                       id="mbr_custom_login_logo_url" 
                                       name="mbr_custom_login_logo_url" 
                                       value="<?php echo esc_attr(get_option('mbr_custom_login_logo_url', home_url())); ?>" 
                                       class="regular-text">
                                <p class="description">
                                    <?php _e('Where should the logo link to?', 'mbr-custom-login'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_logo_text">
                                    <?php _e('Logo Title Text', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="text" 
                                       id="mbr_custom_login_logo_text" 
                                       name="mbr_custom_login_logo_text" 
                                       value="<?php echo esc_attr(get_option('mbr_custom_login_logo_text', get_bloginfo('name'))); ?>" 
                                       class="regular-text">
                                <p class="description">
                                    <?php _e('Hover text for the logo', 'mbr-custom-login'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_message">
                                    <?php _e('Welcome Message', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <textarea id="mbr_custom_login_message" 
                                          name="mbr_custom_login_message" 
                                          rows="3" 
                                          class="large-text"><?php echo esc_textarea(get_option('mbr_custom_login_message', '')); ?></textarea>
                                <p class="description">
                                    <?php _e('Optional message to display above the login form', 'mbr-custom-login'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <?php _e('Background Type', 'mbr-custom-login'); ?>
                            </th>
                            <td>
                                <?php $bg_type = get_option('mbr_custom_login_bg_type', 'color'); ?>
                                <label>
                                    <input type="radio" 
                                           name="mbr_custom_login_bg_type" 
                                           value="color" 
                                           <?php checked($bg_type, 'color'); ?>
                                           class="bg-type-radio">
                                    <?php _e('Solid Color', 'mbr-custom-login'); ?>
                                </label><br>
                                <label>
                                    <input type="radio" 
                                           name="mbr_custom_login_bg_type" 
                                           value="gradient" 
                                           <?php checked($bg_type, 'gradient'); ?>
                                           class="bg-type-radio">
                                    <?php _e('Gradient', 'mbr-custom-login'); ?>
                                </label><br>
                                <label>
                                    <input type="radio" 
                                           name="mbr_custom_login_bg_type" 
                                           value="image" 
                                           <?php checked($bg_type, 'image'); ?>
                                           class="bg-type-radio">
                                    <?php _e('Image', 'mbr-custom-login'); ?>
                                </label>
                            </td>
                        </tr>
                        <tr class="bg-option bg-color" <?php echo ($bg_type !== 'color') ? 'style="display:none;"' : ''; ?>>
                            <th scope="row">
                                <label for="mbr_custom_login_bg_color">
                                    <?php _e('Background Color', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="text" 
                                       id="mbr_custom_login_bg_color" 
                                       name="mbr_custom_login_bg_color" 
                                       value="<?php echo esc_attr(get_option('mbr_custom_login_bg_color', '#f0f0f1')); ?>" 
                                       class="color-picker">
                            </td>
                        </tr>
                        <tr class="bg-option bg-gradient" <?php echo ($bg_type !== 'gradient') ? 'style="display:none;"' : ''; ?>>
                            <th scope="row">
                                <label for="mbr_custom_login_bg_gradient_start">
                                    <?php _e('Gradient Start Color', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="text" 
                                       id="mbr_custom_login_bg_gradient_start" 
                                       name="mbr_custom_login_bg_gradient_start" 
                                       value="<?php echo esc_attr(get_option('mbr_custom_login_bg_gradient_start', '#667eea')); ?>" 
                                       class="color-picker">
                            </td>
                        </tr>
                        <tr class="bg-option bg-gradient" <?php echo ($bg_type !== 'gradient') ? 'style="display:none;"' : ''; ?>>
                            <th scope="row">
                                <label for="mbr_custom_login_bg_gradient_end">
                                    <?php _e('Gradient End Color', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="text" 
                                       id="mbr_custom_login_bg_gradient_end" 
                                       name="mbr_custom_login_bg_gradient_end" 
                                       value="<?php echo esc_attr(get_option('mbr_custom_login_bg_gradient_end', '#764ba2')); ?>" 
                                       class="color-picker">
                            </td>
                        </tr>
                        <tr class="bg-option bg-gradient" <?php echo ($bg_type !== 'gradient') ? 'style="display:none;"' : ''; ?>>
                            <th scope="row">
                                <label for="mbr_custom_login_bg_gradient_direction">
                                    <?php _e('Gradient Direction', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <select id="mbr_custom_login_bg_gradient_direction" name="mbr_custom_login_bg_gradient_direction">
                                    <option value="to bottom" <?php selected(get_option('mbr_custom_login_bg_gradient_direction', 'to bottom right'), 'to bottom'); ?>><?php _e('Top to Bottom', 'mbr-custom-login'); ?></option>
                                    <option value="to top" <?php selected(get_option('mbr_custom_login_bg_gradient_direction', 'to bottom right'), 'to top'); ?>><?php _e('Bottom to Top', 'mbr-custom-login'); ?></option>
                                    <option value="to right" <?php selected(get_option('mbr_custom_login_bg_gradient_direction', 'to bottom right'), 'to right'); ?>><?php _e('Left to Right', 'mbr-custom-login'); ?></option>
                                    <option value="to left" <?php selected(get_option('mbr_custom_login_bg_gradient_direction', 'to bottom right'), 'to left'); ?>><?php _e('Right to Left', 'mbr-custom-login'); ?></option>
                                    <option value="to bottom right" <?php selected(get_option('mbr_custom_login_bg_gradient_direction', 'to bottom right'), 'to bottom right'); ?>><?php _e('Diagonal (Top-Left to Bottom-Right)', 'mbr-custom-login'); ?></option>
                                    <option value="to bottom left" <?php selected(get_option('mbr_custom_login_bg_gradient_direction', 'to bottom right'), 'to bottom left'); ?>><?php _e('Diagonal (Top-Right to Bottom-Left)', 'mbr-custom-login'); ?></option>
                                </select>
                            </td>
                        </tr>
                        <tr class="bg-option bg-image" <?php echo ($bg_type !== 'image') ? 'style="display:none;"' : ''; ?>>
                            <th scope="row">
                                <label for="mbr_custom_login_bg_image">
                                    <?php _e('Background Image', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="hidden" 
                                       id="mbr_custom_login_bg_image" 
                                       name="mbr_custom_login_bg_image" 
                                       value="<?php echo esc_attr(get_option('mbr_custom_login_bg_image', '')); ?>">
                                <div id="bg-image-preview" style="margin-bottom: 10px;">
                                    <?php 
                                    $bg_img_url = get_option('mbr_custom_login_bg_image', '');
                                    if (!empty($bg_img_url)): 
                                    ?>
                                        <img src="<?php echo esc_url($bg_img_url); ?>" style="max-width: 400px; max-height: 200px; display: block; margin-bottom: 10px;">
                                    <?php endif; ?>
                                </div>
                                <button type="button" class="button" id="upload_bg_image_button">
                                    <?php _e('Choose Background Image', 'mbr-custom-login'); ?>
                                </button>
                                <button type="button" class="button" id="remove_bg_image_button" <?php echo empty($bg_img_url) ? 'style="display:none;"' : ''; ?>>
                                    <?php _e('Remove Background', 'mbr-custom-login'); ?>
                                </button>
                                <p class="description">
                                    <?php _e('Recommended size: 1920x1080 pixels or larger for best results', 'mbr-custom-login'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_button_color">
                                    <?php _e('Button Color', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="text" 
                                       id="mbr_custom_login_button_color" 
                                       name="mbr_custom_login_button_color" 
                                       value="<?php echo esc_attr(get_option('mbr_custom_login_button_color', '#2271b1')); ?>" 
                                       class="color-picker">
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <?php _e('Form Style', 'mbr-custom-login'); ?>
                            </th>
                            <td>
                                <?php $form_style = get_option('mbr_custom_login_form_style', 'default'); ?>
                                <label style="display: block; margin-bottom: 10px;">
                                    <input type="radio" 
                                           name="mbr_custom_login_form_style" 
                                           value="default" 
                                           <?php checked($form_style, 'default'); ?>>
                                    <?php _e('Default (Standard WordPress)', 'mbr-custom-login'); ?>
                                </label>
                                <label style="display: block; margin-bottom: 10px;">
                                    <input type="radio" 
                                           name="mbr_custom_login_form_style" 
                                           value="dark" 
                                           <?php checked($form_style, 'dark'); ?>>
                                    <?php _e('Dark Mode', 'mbr-custom-login'); ?>
                                    <span class="description" style="display: block; margin-left: 25px; color: #666;">
                                        <?php _e('Dark themed form with light text - works great with colorful backgrounds', 'mbr-custom-login'); ?>
                                    </span>
                                </label>
                                <label style="display: block; margin-bottom: 10px;">
                                    <input type="radio" 
                                           name="mbr_custom_login_form_style" 
                                           value="glass" 
                                           <?php checked($form_style, 'glass'); ?>>
                                    <?php _e('Glassmorphism', 'mbr-custom-login'); ?>
                                    <span class="description" style="display: block; margin-left: 25px; color: #666;">
                                        <?php _e('Modern frosted glass effect with blur - best with gradient or image backgrounds', 'mbr-custom-login'); ?>
                                    </span>
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_css">
                                    <?php _e('Custom CSS', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <textarea id="mbr_custom_login_css" 
                                          name="mbr_custom_login_css" 
                                          rows="10" 
                                          class="large-text code"><?php echo esc_textarea(get_option('mbr_custom_login_css', '')); ?></textarea>
                                <p class="description">
                                    <?php _e('Advanced: Add your own CSS to further customize the login page', 'mbr-custom-login'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_font_family">
                                    <?php _e('Font Family', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <select id="mbr_custom_login_font_family" name="mbr_custom_login_font_family">
                                    <option value="default" <?php selected(get_option('mbr_custom_login_font_family', 'default'), 'default'); ?>><?php _e('Default WordPress Font', 'mbr-custom-login'); ?></option>
                                    <option value="system" <?php selected(get_option('mbr_custom_login_font_family', 'default'), 'system'); ?>><?php _e('System Font Stack', 'mbr-custom-login'); ?></option>
                                    <option value="Roboto" <?php selected(get_option('mbr_custom_login_font_family', 'default'), 'Roboto'); ?>>Roboto</option>
                                    <option value="Open+Sans" <?php selected(get_option('mbr_custom_login_font_family', 'default'), 'Open+Sans'); ?>>Open Sans</option>
                                    <option value="Lato" <?php selected(get_option('mbr_custom_login_font_family', 'default'), 'Lato'); ?>>Lato</option>
                                    <option value="Montserrat" <?php selected(get_option('mbr_custom_login_font_family', 'default'), 'Montserrat'); ?>>Montserrat</option>
                                    <option value="Raleway" <?php selected(get_option('mbr_custom_login_font_family', 'default'), 'Raleway'); ?>>Raleway</option>
                                    <option value="Poppins" <?php selected(get_option('mbr_custom_login_font_family', 'default'), 'Poppins'); ?>>Poppins</option>
                                    <option value="Inter" <?php selected(get_option('mbr_custom_login_font_family', 'default'), 'Inter'); ?>>Inter</option>
                                    <option value="Playfair+Display" <?php selected(get_option('mbr_custom_login_font_family', 'default'), 'Playfair+Display'); ?>>Playfair Display</option>
                                    <option value="Merriweather" <?php selected(get_option('mbr_custom_login_font_family', 'default'), 'Merriweather'); ?>>Merriweather</option>
                                </select>
                                <p class="description">
                                    <?php _e('Choose a custom font for the login page (Google Fonts)', 'mbr-custom-login'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_animation">
                                    <?php _e('Form Animation', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <select id="mbr_custom_login_animation" name="mbr_custom_login_animation">
                                    <option value="none" <?php selected(get_option('mbr_custom_login_animation', 'none'), 'none'); ?>><?php _e('None', 'mbr-custom-login'); ?></option>
                                    <option value="fade" <?php selected(get_option('mbr_custom_login_animation', 'none'), 'fade'); ?>><?php _e('Fade In', 'mbr-custom-login'); ?></option>
                                    <option value="slide" <?php selected(get_option('mbr_custom_login_animation', 'none'), 'slide'); ?>><?php _e('Slide Down', 'mbr-custom-login'); ?></option>
                                    <option value="zoom" <?php selected(get_option('mbr_custom_login_animation', 'none'), 'zoom'); ?>><?php _e('Zoom In', 'mbr-custom-login'); ?></option>
                                    <option value="bounce" <?php selected(get_option('mbr_custom_login_animation', 'none'), 'bounce'); ?>><?php _e('Bounce', 'mbr-custom-login'); ?></option>
                                </select>
                                <p class="description">
                                    <?php _e('Animation effect when the login form loads', 'mbr-custom-login'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_box_shadow">
                                    <?php _e('Form Shadow', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <select id="mbr_custom_login_box_shadow" name="mbr_custom_login_box_shadow">
                                    <option value="none" <?php selected(get_option('mbr_custom_login_box_shadow', 'medium'), 'none'); ?>><?php _e('None', 'mbr-custom-login'); ?></option>
                                    <option value="subtle" <?php selected(get_option('mbr_custom_login_box_shadow', 'medium'), 'subtle'); ?>><?php _e('Subtle', 'mbr-custom-login'); ?></option>
                                    <option value="medium" <?php selected(get_option('mbr_custom_login_box_shadow', 'medium'), 'medium'); ?>><?php _e('Medium', 'mbr-custom-login'); ?></option>
                                    <option value="strong" <?php selected(get_option('mbr_custom_login_box_shadow', 'medium'), 'strong'); ?>><?php _e('Strong', 'mbr-custom-login'); ?></option>
                                    <option value="glow" <?php selected(get_option('mbr_custom_login_box_shadow', 'medium'), 'glow'); ?>><?php _e('Glow (uses button color)', 'mbr-custom-login'); ?></option>
                                </select>
                                <p class="description">
                                    <?php _e('Shadow depth for the login form box', 'mbr-custom-login'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_footer_text">
                                    <?php _e('Footer Text', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <textarea id="mbr_custom_login_footer_text" 
                                          name="mbr_custom_login_footer_text" 
                                          rows="3" 
                                          class="large-text"><?php echo esc_textarea(get_option('mbr_custom_login_footer_text', '')); ?></textarea>
                                <p class="description">
                                    <?php _e('Custom footer text or HTML to display at the bottom of the login page', 'mbr-custom-login'); ?>
                                </p>
                            </td>
                        </tr>
                    </table>
                    <?php submit_button(); ?>
                </form>
            <?php else: // Security tab ?>
                <form method="post" action="options.php">
                    <?php settings_fields('mbr_custom_login_security'); ?>
                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row">
                                <?php _e('Limit Login Attempts', 'mbr-custom-login'); ?>
                            </th>
                            <td>
                                <label>
                                    <input type="checkbox"
                                           name="mbr_custom_login_limit_enabled"
                                           value="1"
                                           <?php checked(get_option('mbr_custom_login_limit_enabled', 0), 1); ?>>
                                    <?php _e('Lock out an IP address after too many failed login attempts', 'mbr-custom-login'); ?>
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_max_attempts">
                                    <?php _e('Max Failed Attempts', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="number" min="1" max="100"
                                       id="mbr_custom_login_max_attempts"
                                       name="mbr_custom_login_max_attempts"
                                       value="<?php echo esc_attr(get_option('mbr_custom_login_max_attempts', 5)); ?>"
                                       class="small-text">
                                <p class="description">
                                    <?php _e('Number of failed attempts allowed before an IP is locked out.', 'mbr-custom-login'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_attempt_window">
                                    <?php _e('Attempt Window (minutes)', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="number" min="1" max="1440"
                                       id="mbr_custom_login_attempt_window"
                                       name="mbr_custom_login_attempt_window"
                                       value="<?php echo esc_attr(get_option('mbr_custom_login_attempt_window', 15)); ?>"
                                       class="small-text">
                                <p class="description">
                                    <?php _e('Failed attempts are counted within this rolling window. Older failures are forgiven.', 'mbr-custom-login'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_lockout_duration">
                                    <?php _e('Lockout Duration (minutes)', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="number" min="1" max="10080"
                                       id="mbr_custom_login_lockout_duration"
                                       name="mbr_custom_login_lockout_duration"
                                       value="<?php echo esc_attr(get_option('mbr_custom_login_lockout_duration', 15)); ?>"
                                       class="small-text">
                                <p class="description">
                                    <?php _e('How long a locked-out IP must wait before it can try again.', 'mbr-custom-login'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <?php _e('Behind a Proxy / CDN', 'mbr-custom-login'); ?>
                            </th>
                            <td>
                                <label>
                                    <input type="checkbox"
                                           name="mbr_custom_login_behind_proxy"
                                           value="1"
                                           <?php checked(get_option('mbr_custom_login_behind_proxy', 0), 1); ?>>
                                    <?php _e('My site sits behind Cloudflare or another reverse proxy', 'mbr-custom-login'); ?>
                                </label>
                                <p class="description">
                                    <?php _e('Enable this so the real visitor IP is read from proxy headers instead of the proxy\'s own address. Leave off if you are not behind a proxy, as these headers can otherwise be spoofed.', 'mbr-custom-login'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_whitelist_ips">
                                    <?php _e('Whitelisted IPs', 'mbr-custom-login'); ?>
                                </label>
                            </th>
                            <td>
                                <textarea id="mbr_custom_login_whitelist_ips"
                                          name="mbr_custom_login_whitelist_ips"
                                          rows="4"
                                          class="large-text code"><?php echo esc_textarea(get_option('mbr_custom_login_whitelist_ips', '')); ?></textarea>
                                <p class="description">
                                    <?php
                                    printf(
                                        __('One IP address per line. These are never locked out. Your current IP: %s', 'mbr-custom-login'),
                                        '<code>' . esc_html($this->get_client_ip()) . '</code>'
                                    );
                                    ?>
                                </p>
                            </td>
                        </tr>
                    </table>
                    <?php submit_button(); ?>
                </form>

                <?php
                // Active lockouts table.
                $data = $this->get_attempt_data();
                $now  = time();
                $locked = array();
                foreach ($data as $key => $rec) {
                    if (!empty($rec['lock_until']) && $rec['lock_until'] > $now) {
                        $locked[$key] = $rec;
                    }
                }
                ?>
                <h2><?php _e('Currently Locked Out', 'mbr-custom-login'); ?></h2>
                <?php if (empty($locked)): ?>
                    <p><?php _e('No IP addresses are currently locked out.', 'mbr-custom-login'); ?></p>
                <?php else: ?>
                    <table class="widefat striped" style="max-width:640px;">
                        <thead>
                            <tr>
                                <th><?php _e('IP Address', 'mbr-custom-login'); ?></th>
                                <th><?php _e('Unlocks In', 'mbr-custom-login'); ?></th>
                                <th><?php _e('Action', 'mbr-custom-login'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($locked as $key => $rec):
                                $mins = max(1, (int) ceil(($rec['lock_until'] - $now) / 60));
                                $unlock_url = wp_nonce_url(
                                    admin_url('options-general.php?page=mbr-custom-login&tab=security&mbr_unlock=' . $key),
                                    'mbr_unlock'
                                );
                            ?>
                                <tr>
                                    <td><code><?php echo esc_html(isset($rec['ip']) ? $rec['ip'] : __('unknown', 'mbr-custom-login')); ?></code></td>
                                    <td><?php printf(_n('%d minute', '%d minutes', $mins, 'mbr-custom-login'), $mins); ?></td>
                                    <td><a href="<?php echo esc_url($unlock_url); ?>" class="button button-small"><?php _e('Unlock', 'mbr-custom-login'); ?></a></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    <p>
                        <a href="<?php echo esc_url(wp_nonce_url(admin_url('options-general.php?page=mbr-custom-login&tab=security&mbr_unlock=all'), 'mbr_unlock')); ?>"
                           class="button"><?php _e('Clear All Lockouts', 'mbr-custom-login'); ?></a>
                    </p>
                <?php endif; ?>
            <?php endif; ?>
        </div>
        <?php
    }
}

// Initialize the plugin
function mbr_custom_login_init() {
    return MBR_Custom_Login::get_instance();
}
add_action('plugins_loaded', 'mbr_custom_login_init');

// Activation hook
register_activation_hook(__FILE__, function() {
    // Set default options
    add_option('mbr_custom_login_slug', 'login');
    add_option('mbr_custom_login_emergency_key', wp_generate_password(32, false));

    // Login limiting defaults (off until the admin enables it)
    add_option('mbr_custom_login_limit_enabled', 0);
    add_option('mbr_custom_login_max_attempts', 5);
    add_option('mbr_custom_login_attempt_window', 15);
    add_option('mbr_custom_login_lockout_duration', 15);
    add_option('mbr_custom_login_behind_proxy', 0);
    add_option('mbr_custom_login_whitelist_ips', '');
    
    // Flush rewrite rules
    flush_rewrite_rules();
});

// Deactivation hook
register_deactivation_hook(__FILE__, function() {
    flush_rewrite_rules();
});
