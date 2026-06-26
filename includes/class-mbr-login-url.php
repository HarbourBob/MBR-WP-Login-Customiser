<?php
/**
 * Custom login URL handling and standard-login blocking.
 *
 * @package MBR_Login_Customiser
 */

if (!defined('ABSPATH')) {
    exit;
}

class MBR_Login_Url {

    private $login_slug = '';
    private $emergency_key = '';

    /**
     * Load the slug and emergency key via the options seam.
     */
    public function __construct() {
        $this->login_slug    = MBR_Login_Options::get('mbr_custom_login_slug', 'login');
        $this->emergency_key = MBR_Login_Options::get('mbr_custom_login_emergency_key', '');
    }

    /**
     * Register WordPress hooks for this module.
     */
    public function register_hooks() {
        add_action('init', array($this, 'handle_custom_login_url'));
        add_filter('site_url', array($this, 'filter_site_url'), 10, 4);
        add_filter('wp_redirect', array($this, 'filter_wp_redirect'), 10, 2);
        add_action('init', array($this, 'block_standard_login'));
    }

    /**
     * Handle custom login URL requests
     */
    public function handle_custom_login_url() {
        // Check if we're on the custom login URL
        $raw_uri     = isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '';
        $request_uri = wp_parse_url($raw_uri, PHP_URL_PATH);
        $request_uri = rtrim((string) $request_uri, '/');
        $home_path = trim(wp_parse_url(home_url(), PHP_URL_PATH), '/');
        
        // Remove home path from request URI
        if ($home_path && strpos($request_uri, $home_path) === 0) {
            $request_uri = substr($request_uri, strlen($home_path));
        }
        $request_uri = ltrim($request_uri, '/');
        
        // Check for emergency access.
        // hash_equals() guarantees a constant-time comparison so the secret
        // key cannot be recovered by measuring response timing.
        if (isset($_GET['mbr_emergency']) && !empty($this->emergency_key)) {
            $supplied = (string) wp_unslash($_GET['mbr_emergency']);
            if (hash_equals((string) $this->emergency_key, $supplied)) {
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
        $query_string = isset($_SERVER['QUERY_STRING']) ? wp_unslash($_SERVER['QUERY_STRING']) : '';
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
        $this->set_login_token_cookie($token, time() + 300);
        
        require_once ABSPATH . 'wp-login.php';
        exit;
    }

    /**
     * Set the short-lived login pass-through cookie.
     *
     * Adds SameSite=Lax. PHP 7.3+ accepts an options array; older versions
     * fall back to the legacy signature so the plugin still works on PHP 7.0.
     */
    private function set_login_token_cookie($token, $expires) {
        if (PHP_VERSION_ID >= 70300) {
            setcookie('mbr_login_token', $token, array(
                'expires'  => $expires,
                'path'     => COOKIEPATH,
                'domain'   => COOKIE_DOMAIN,
                'secure'   => is_ssl(),
                'httponly' => true,
                'samesite' => 'Lax',
            ));
        } else {
            setcookie('mbr_login_token', $token, $expires, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
        }
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
            wp_die(esc_html__('Page not found', 'mbr-login-customiser'), '404 - Not Found', array('response' => 404));
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
}
