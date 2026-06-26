<?php
/**
 * Admin settings screen and option registration.
 *
 * @package MBR_Login_Customiser
 */

if (!defined('ABSPATH')) {
    exit;
}

class MBR_Login_Admin {

    private $login_slug = '';
    private $emergency_key = '';

    /**
     * Security module, injected so the screen can show and clear lockouts.
     *
     * @var MBR_Login_Security
     */
    private $security;

    /**
     * Log module, injected for the Logs tab viewer.
     *
     * @var MBR_Login_Log
     */
    private $log;

    /**
     * 2FA module, injected for the 2FA tab.
     *
     * @var MBR_Login_2FA
     */
    private $twofa;

    /**
     * @param MBR_Login_Security $security Shared security module instance.
     * @param MBR_Login_Log      $log      Shared log module instance.
     * @param MBR_Login_2FA      $twofa    Shared 2FA module instance.
     */
    public function __construct($security, $log, $twofa) {
        $this->security      = $security;
        $this->log           = $log;
        $this->twofa         = $twofa;
        $this->login_slug    = MBR_Login_Options::get('mbr_custom_login_slug', 'login');
        $this->emergency_key = MBR_Login_Options::get('mbr_custom_login_emergency_key', '');
    }

    /**
     * Register WordPress hooks for this module.
     */
    public function register_hooks() {
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
    }

    /**
     * Add admin menu
     */
    public function add_admin_menu() {
        $page_hook = add_options_page(
            __('MBR Login Customiser', 'mbr-login-customiser'),
            __('Login Customiser', 'mbr-login-customiser'),
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
        
        // Enqueue custom admin script. Use the plugin-root URL constant rather
        // than plugin_dir_url(__FILE__): this file lives in includes/, so
        // __FILE__ would resolve the script to includes/admin.js (a 404).
        wp_enqueue_script(
            'mbr-custom-login-admin',
            MBR_CUSTOM_LOGIN_PLUGIN_URL . 'admin.js',
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
        register_setting('mbr_custom_login_appearance', 'mbr_custom_login_bg_gradient_direction', array(
            'sanitize_callback' => array($this, 'sanitize_gradient_direction')
        ));
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
        register_setting('mbr_custom_login_security', 'mbr_custom_login_progressive_enabled', array(
            'sanitize_callback' => array($this, 'sanitize_checkbox')
        ));
        register_setting('mbr_custom_login_security', 'mbr_custom_login_lockout_multiplier', array(
            'sanitize_callback' => array($this, 'sanitize_multiplier')
        ));
        register_setting('mbr_custom_login_security', 'mbr_custom_login_lockout_max', array(
            'sanitize_callback' => array($this, 'sanitize_lockout_max')
        ));
        register_setting('mbr_custom_login_security', 'mbr_custom_login_offense_memory', array(
            'sanitize_callback' => array($this, 'sanitize_offense_memory')
        ));
        register_setting('mbr_custom_login_security', 'mbr_custom_login_behind_proxy', array(
            'sanitize_callback' => array($this, 'sanitize_checkbox')
        ));
        register_setting('mbr_custom_login_security', 'mbr_custom_login_proxy_header', array(
            'sanitize_callback' => array($this, 'sanitize_proxy_header')
        ));
        register_setting('mbr_custom_login_security', 'mbr_custom_login_whitelist_ips', array(
            'sanitize_callback' => array($this, 'sanitize_ip_list')
        ));
        register_setting('mbr_custom_login_security', 'mbr_custom_login_blacklist_ips', array(
            'sanitize_callback' => array($this, 'sanitize_ip_list')
        ));
        register_setting('mbr_custom_login_security', 'mbr_custom_login_whitelist_only', array(
            'sanitize_callback' => array($this, 'sanitize_checkbox')
        ));

        // Logging settings.
        register_setting('mbr_custom_login_logging', 'mbr_custom_login_log_enabled', array(
            'sanitize_callback' => array($this, 'sanitize_checkbox')
        ));
        register_setting('mbr_custom_login_logging', 'mbr_custom_login_log_retention_days', array(
            'sanitize_callback' => array($this, 'sanitize_retention_days')
        ));

        // Redirect settings.
        register_setting('mbr_custom_login_redirects', 'mbr_custom_login_redirect_enabled', array(
            'sanitize_callback' => array($this, 'sanitize_checkbox')
        ));
        register_setting('mbr_custom_login_redirects', 'mbr_custom_login_redirect_rules', array(
            'sanitize_callback' => array($this, 'sanitize_redirect_rules')
        ));
        register_setting('mbr_custom_login_redirects', 'mbr_custom_login_redirect_default', array(
            'sanitize_callback' => array($this, 'sanitize_redirect_url')
        ));
        register_setting('mbr_custom_login_redirects', 'mbr_custom_login_logout_redirect', array(
            'sanitize_callback' => array($this, 'sanitize_redirect_url')
        ));

        // Schedule (time-based access) settings.
        register_setting('mbr_custom_login_schedule', 'mbr_custom_login_time_enabled', array(
            'sanitize_callback' => array($this, 'sanitize_checkbox')
        ));
        register_setting('mbr_custom_login_schedule', 'mbr_custom_login_time_rules', array(
            'sanitize_callback' => array($this, 'sanitize_time_rules')
        ));

        // Two-factor settings.
        register_setting('mbr_custom_login_2fa', 'mbr_custom_login_2fa_enabled', array(
            'sanitize_callback' => array($this, 'sanitize_checkbox')
        ));
        register_setting('mbr_custom_login_2fa', 'mbr_custom_login_2fa_app_passwords', array(
            'sanitize_callback' => array($this, 'sanitize_app_passwords_policy')
        ));
    }

    /**
     * Sanitize a checkbox value to 0/1.
     */
    public function sanitize_checkbox($value) {
        return !empty($value) ? 1 : 0;
    }

    /**
     * Whitelist the Application Passwords policy value.
     */
    public function sanitize_app_passwords_policy($value) {
        return ($value === 'allow') ? 'allow' : 'block';
    }

    /**
     * Sanitize the log retention period (days), clamped to a sane range.
     */
    public function sanitize_retention_days($value) {
        $days = absint($value);
        if ($days < 1) {
            $days = 30;
        }
        return min(3650, $days);
    }

    /**
     * Sanitize the progressive lockout multiplier (1–10).
     */
    public function sanitize_multiplier($value) {
        $n = absint($value);
        if ($n < 1) {
            $n = 2;
        }
        return min(10, $n);
    }

    /**
     * Sanitize the maximum lockout duration in minutes (>= 1).
     */
    public function sanitize_lockout_max($value) {
        $n = absint($value);
        if ($n < 1) {
            $n = 1440;
        }
        return min(525600, $n); // one year, an absurd-but-finite ceiling
    }

    /**
     * Sanitize the offence-memory window in hours (1–8760).
     */
    public function sanitize_offense_memory($value) {
        $n = absint($value);
        if ($n < 1) {
            $n = 24;
        }
        return min(8760, $n);
    }

    /**
     * Sanitize a redirect URL: keep an http(s) URL as-is, otherwise treat the
     * value as a site-relative path. Empty is allowed (means "no redirect").
     */
    public function sanitize_redirect_url($url) {
        $url = trim((string) $url);
        if ($url === '') {
            return '';
        }
        if (preg_match('#^https?://#i', $url)) {
            return esc_url_raw($url);
        }
        return '/' . ltrim(esc_url_raw($url), '/');
    }

    /**
     * Sanitize the repeatable redirect-rule list, dropping incomplete rows.
     */
    public function sanitize_redirect_rules($value) {        $out = array();
        if (!is_array($value)) {
            return $out;
        }
        foreach ($value as $row) {
            if (!is_array($row)) {
                continue;
            }
            $type = (isset($row['type']) && 'user' === $row['type']) ? 'user' : 'role';
            $val  = isset($row['value']) ? sanitize_text_field($row['value']) : '';
            $url  = isset($row['url']) ? $this->sanitize_redirect_url($row['url']) : '';
            if ($val === '' || $url === '') {
                continue; // skip blank/incomplete rows
            }
            $out[] = array('type' => $type, 'value' => $val, 'url' => $url);
        }
        return $out;
    }

    /**
     * Sanitize the weekly schedule: a fixed map of day (0–6) to an
     * enabled flag and start/end 'HH:MM' times.
     */
    public function sanitize_time_rules($value) {
        $out = array();
        for ($d = 0; $d <= 6; $d++) {
            $row = (is_array($value) && isset($value[$d]) && is_array($value[$d])) ? $value[$d] : array();
            $out[$d] = array(
                'enabled' => empty($row['enabled']) ? 0 : 1,
                'start'   => $this->sanitize_hm(isset($row['start']) ? $row['start'] : ''),
                'end'     => $this->sanitize_hm(isset($row['end']) ? $row['end'] : ''),
            );
        }
        return $out;
    }

    /**
     * Normalise an 'HH:MM' time, returning '' if invalid.
     */
    private function sanitize_hm($v) {
        $v = trim((string) $v);
        if (preg_match('/^(\d{1,2}):(\d{2})$/', $v, $m) && (int) $m[1] <= 23 && (int) $m[2] <= 59) {
            return sprintf('%02d:%02d', (int) $m[1], (int) $m[2]);
        }
        return '';
    }

    /**
     * Sanitize the chosen trusted proxy header against an allowlist.
     */
    public function sanitize_proxy_header($value) {
        $allowed = array(
            'HTTP_CF_CONNECTING_IP',
            'HTTP_TRUE_CLIENT_IP',
            'HTTP_X_REAL_IP',
            'HTTP_X_FORWARDED_FOR',
        );
        return in_array($value, $allowed, true) ? $value : 'HTTP_CF_CONNECTING_IP';
    }

    /**
     * Sanitize a newline-separated IP whitelist, keeping only valid IPs.
     */
    public function sanitize_ip_list($list) {
        $valid = array();
        $entries = preg_split('/[\r\n]+/', (string) $list);
        foreach ($entries as $entry) {
            $entry = trim($entry);
            if ($entry === '') {
                continue;
            }
            if (strpos($entry, '/') !== false) {
                // CIDR range: validate the address and the prefix length.
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
     * Sanitize gradient direction against a fixed allowlist.
     */
    public function sanitize_gradient_direction($direction) {
        $allowed = array(
            'to bottom', 'to top', 'to right', 'to left',
            'to bottom right', 'to bottom left',
        );
        return in_array($direction, $allowed, true) ? $direction : 'to bottom right';
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
                __('This slug is reserved. Please choose another.', 'mbr-login-customiser')
            );
            return get_option('mbr_custom_login_slug', 'login');
        }
        
        return $slug;
    }
    
    /**
     * Sanitize custom CSS
     */
    public function sanitize_css($css) {
        // Strip any HTML tags, then neutralise any attempt to break out of the
        // <style> element (e.g. a stray "</style>") so the value is safe to print.
        $css = wp_strip_all_tags((string) $css);
        $css = preg_replace('#</?\s*style#i', '', $css);
        return $css;
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
                    $this->security->save_attempt_data(array());
                } else {
                    $data = $this->security->get_attempt_data();
                    if (isset($data[$target])) {
                        unset($data[$target]);
                        $this->security->save_attempt_data($data);
                    }
                }
                echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Lockout(s) cleared.', 'mbr-login-customiser') . '</p></div>';
            }
        }
        
        // Handle a clear-log request.
        if ($active_tab === 'logs' && isset($_GET['mbr_clear_log']) && isset($_GET['_wpnonce'])) {
            if (wp_verify_nonce(sanitize_text_field($_GET['_wpnonce']), 'mbr_clear_log')) {
                $this->log->clear();
                echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Log cleared.', 'mbr-login-customiser') . '</p></div>';
            }
        }

        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            
            <h2 class="nav-tab-wrapper">
                <a href="?page=mbr-custom-login&tab=url" class="nav-tab <?php echo $active_tab === 'url' ? 'nav-tab-active' : ''; ?>">
                    <?php esc_html_e('Login URL', 'mbr-login-customiser'); ?>
                </a>
                <a href="?page=mbr-custom-login&tab=appearance" class="nav-tab <?php echo $active_tab === 'appearance' ? 'nav-tab-active' : ''; ?>">
                    <?php esc_html_e('Appearance', 'mbr-login-customiser'); ?>
                </a>
                <a href="?page=mbr-custom-login&tab=security" class="nav-tab <?php echo $active_tab === 'security' ? 'nav-tab-active' : ''; ?>">
                    <?php esc_html_e('Security', 'mbr-login-customiser'); ?>
                </a>
                <a href="?page=mbr-custom-login&tab=logs" class="nav-tab <?php echo $active_tab === 'logs' ? 'nav-tab-active' : ''; ?>">
                    <?php esc_html_e('Logs', 'mbr-login-customiser'); ?>
                </a>
                <a href="?page=mbr-custom-login&tab=redirects" class="nav-tab <?php echo $active_tab === 'redirects' ? 'nav-tab-active' : ''; ?>">
                    <?php esc_html_e('Redirects', 'mbr-login-customiser'); ?>
                </a>
                <a href="?page=mbr-custom-login&tab=schedule" class="nav-tab <?php echo $active_tab === 'schedule' ? 'nav-tab-active' : ''; ?>">
                    <?php esc_html_e('Schedule', 'mbr-login-customiser'); ?>
                </a>
                <a href="?page=mbr-custom-login&tab=2fa" class="nav-tab <?php echo $active_tab === '2fa' ? 'nav-tab-active' : ''; ?>">
                    <?php esc_html_e('Two-Factor', 'mbr-login-customiser'); ?>
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
                                    <?php esc_html_e('Custom Login Slug', 'mbr-login-customiser'); ?>
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
                                        /* translators: %s: the login page URL, wrapped in a <code> element. */
                                        esc_html__('Your login page will be: %s', 'mbr-login-customiser'),
                                        '<code>' . esc_html(home_url($this->login_slug)) . '</code>'
                                    );
                                    ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_emergency_key">
                                    <?php esc_html_e('Emergency Access Key', 'mbr-login-customiser'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="text" 
                                       id="mbr_custom_login_emergency_key" 
                                       name="mbr_custom_login_emergency_key" 
                                       value="<?php echo esc_attr($this->emergency_key); ?>" 
                                       class="regular-text">
                                <p class="description">
                                    <?php esc_html_e('If you forget your login URL, you can access it using:', 'mbr-login-customiser'); ?>
                                    <br>
                                    <code><?php echo esc_html(home_url('?mbr_emergency=' . $this->emergency_key)); ?></code>
                                </p>
                                <button type="button" class="button" onclick="document.getElementById('mbr_custom_login_emergency_key').value = '<?php echo esc_attr(wp_generate_password(32, false)); ?>';">
                                    <?php esc_html_e('Generate New Key', 'mbr-login-customiser'); ?>
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
                                    <?php esc_html_e('Custom Logo', 'mbr-login-customiser'); ?>
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
                                    <?php esc_html_e('Choose Logo', 'mbr-login-customiser'); ?>
                                </button>
                                <button type="button" class="button" id="remove_logo_button" <?php echo empty($logo_url) ? 'style="display:none;"' : ''; ?>>
                                    <?php esc_html_e('Remove Logo', 'mbr-login-customiser'); ?>
                                </button>
                                <p class="description">
                                    <?php esc_html_e('Recommended size: 320x80 pixels', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_logo_url">
                                    <?php esc_html_e('Logo Link URL', 'mbr-login-customiser'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="url" 
                                       id="mbr_custom_login_logo_url" 
                                       name="mbr_custom_login_logo_url" 
                                       value="<?php echo esc_attr(get_option('mbr_custom_login_logo_url', home_url())); ?>" 
                                       class="regular-text">
                                <p class="description">
                                    <?php esc_html_e('Where should the logo link to?', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_logo_text">
                                    <?php esc_html_e('Logo Title Text', 'mbr-login-customiser'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="text" 
                                       id="mbr_custom_login_logo_text" 
                                       name="mbr_custom_login_logo_text" 
                                       value="<?php echo esc_attr(get_option('mbr_custom_login_logo_text', get_bloginfo('name'))); ?>" 
                                       class="regular-text">
                                <p class="description">
                                    <?php esc_html_e('Hover text for the logo', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_message">
                                    <?php esc_html_e('Welcome Message', 'mbr-login-customiser'); ?>
                                </label>
                            </th>
                            <td>
                                <textarea id="mbr_custom_login_message" 
                                          name="mbr_custom_login_message" 
                                          rows="3" 
                                          class="large-text"><?php echo esc_textarea(get_option('mbr_custom_login_message', '')); ?></textarea>
                                <p class="description">
                                    <?php esc_html_e('Optional message to display above the login form', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <?php esc_html_e('Background Type', 'mbr-login-customiser'); ?>
                            </th>
                            <td>
                                <?php $bg_type = get_option('mbr_custom_login_bg_type', 'color'); ?>
                                <label>
                                    <input type="radio" 
                                           name="mbr_custom_login_bg_type" 
                                           value="color" 
                                           <?php checked($bg_type, 'color'); ?>
                                           class="bg-type-radio">
                                    <?php esc_html_e('Solid Color', 'mbr-login-customiser'); ?>
                                </label><br>
                                <label>
                                    <input type="radio" 
                                           name="mbr_custom_login_bg_type" 
                                           value="gradient" 
                                           <?php checked($bg_type, 'gradient'); ?>
                                           class="bg-type-radio">
                                    <?php esc_html_e('Gradient', 'mbr-login-customiser'); ?>
                                </label><br>
                                <label>
                                    <input type="radio" 
                                           name="mbr_custom_login_bg_type" 
                                           value="image" 
                                           <?php checked($bg_type, 'image'); ?>
                                           class="bg-type-radio">
                                    <?php esc_html_e('Image', 'mbr-login-customiser'); ?>
                                </label>
                            </td>
                        </tr>
                        <tr class="bg-option bg-color" <?php echo ($bg_type !== 'color') ? 'style="display:none;"' : ''; ?>>
                            <th scope="row">
                                <label for="mbr_custom_login_bg_color">
                                    <?php esc_html_e('Background Color', 'mbr-login-customiser'); ?>
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
                                    <?php esc_html_e('Gradient Start Color', 'mbr-login-customiser'); ?>
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
                                    <?php esc_html_e('Gradient End Color', 'mbr-login-customiser'); ?>
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
                                    <?php esc_html_e('Gradient Direction', 'mbr-login-customiser'); ?>
                                </label>
                            </th>
                            <td>
                                <select id="mbr_custom_login_bg_gradient_direction" name="mbr_custom_login_bg_gradient_direction">
                                    <option value="to bottom" <?php selected(get_option('mbr_custom_login_bg_gradient_direction', 'to bottom right'), 'to bottom'); ?>><?php esc_html_e('Top to Bottom', 'mbr-login-customiser'); ?></option>
                                    <option value="to top" <?php selected(get_option('mbr_custom_login_bg_gradient_direction', 'to bottom right'), 'to top'); ?>><?php esc_html_e('Bottom to Top', 'mbr-login-customiser'); ?></option>
                                    <option value="to right" <?php selected(get_option('mbr_custom_login_bg_gradient_direction', 'to bottom right'), 'to right'); ?>><?php esc_html_e('Left to Right', 'mbr-login-customiser'); ?></option>
                                    <option value="to left" <?php selected(get_option('mbr_custom_login_bg_gradient_direction', 'to bottom right'), 'to left'); ?>><?php esc_html_e('Right to Left', 'mbr-login-customiser'); ?></option>
                                    <option value="to bottom right" <?php selected(get_option('mbr_custom_login_bg_gradient_direction', 'to bottom right'), 'to bottom right'); ?>><?php esc_html_e('Diagonal (Top-Left to Bottom-Right)', 'mbr-login-customiser'); ?></option>
                                    <option value="to bottom left" <?php selected(get_option('mbr_custom_login_bg_gradient_direction', 'to bottom right'), 'to bottom left'); ?>><?php esc_html_e('Diagonal (Top-Right to Bottom-Left)', 'mbr-login-customiser'); ?></option>
                                </select>
                            </td>
                        </tr>
                        <tr class="bg-option bg-image" <?php echo ($bg_type !== 'image') ? 'style="display:none;"' : ''; ?>>
                            <th scope="row">
                                <label for="mbr_custom_login_bg_image">
                                    <?php esc_html_e('Background Image', 'mbr-login-customiser'); ?>
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
                                    <?php esc_html_e('Choose Background Image', 'mbr-login-customiser'); ?>
                                </button>
                                <button type="button" class="button" id="remove_bg_image_button" <?php echo empty($bg_img_url) ? 'style="display:none;"' : ''; ?>>
                                    <?php esc_html_e('Remove Background', 'mbr-login-customiser'); ?>
                                </button>
                                <p class="description">
                                    <?php esc_html_e('Recommended size: 1920x1080 pixels or larger for best results', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_button_color">
                                    <?php esc_html_e('Button Color', 'mbr-login-customiser'); ?>
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
                                <?php esc_html_e('Form Style', 'mbr-login-customiser'); ?>
                            </th>
                            <td>
                                <?php $form_style = get_option('mbr_custom_login_form_style', 'default'); ?>
                                <label style="display: block; margin-bottom: 10px;">
                                    <input type="radio" 
                                           name="mbr_custom_login_form_style" 
                                           value="default" 
                                           <?php checked($form_style, 'default'); ?>>
                                    <?php esc_html_e('Default (Standard WordPress)', 'mbr-login-customiser'); ?>
                                </label>
                                <label style="display: block; margin-bottom: 10px;">
                                    <input type="radio" 
                                           name="mbr_custom_login_form_style" 
                                           value="dark" 
                                           <?php checked($form_style, 'dark'); ?>>
                                    <?php esc_html_e('Dark Mode', 'mbr-login-customiser'); ?>
                                    <span class="description" style="display: block; margin-left: 25px; color: #666;">
                                        <?php esc_html_e('Dark themed form with light text - works great with colorful backgrounds', 'mbr-login-customiser'); ?>
                                    </span>
                                </label>
                                <label style="display: block; margin-bottom: 10px;">
                                    <input type="radio" 
                                           name="mbr_custom_login_form_style" 
                                           value="glass" 
                                           <?php checked($form_style, 'glass'); ?>>
                                    <?php esc_html_e('Glassmorphism', 'mbr-login-customiser'); ?>
                                    <span class="description" style="display: block; margin-left: 25px; color: #666;">
                                        <?php esc_html_e('Modern frosted glass effect with blur - best with gradient or image backgrounds', 'mbr-login-customiser'); ?>
                                    </span>
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_css">
                                    <?php esc_html_e('Custom CSS', 'mbr-login-customiser'); ?>
                                </label>
                            </th>
                            <td>
                                <textarea id="mbr_custom_login_css" 
                                          name="mbr_custom_login_css" 
                                          rows="10" 
                                          class="large-text code"><?php echo esc_textarea(get_option('mbr_custom_login_css', '')); ?></textarea>
                                <p class="description">
                                    <?php esc_html_e('Advanced: Add your own CSS to further customize the login page', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_font_family">
                                    <?php esc_html_e('Font Family', 'mbr-login-customiser'); ?>
                                </label>
                            </th>
                            <td>
                                <select id="mbr_custom_login_font_family" name="mbr_custom_login_font_family">
                                    <option value="default" <?php selected(get_option('mbr_custom_login_font_family', 'default'), 'default'); ?>><?php esc_html_e('Default WordPress Font', 'mbr-login-customiser'); ?></option>
                                    <option value="system" <?php selected(get_option('mbr_custom_login_font_family', 'default'), 'system'); ?>><?php esc_html_e('System Font Stack', 'mbr-login-customiser'); ?></option>
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
                                    <?php esc_html_e('Choose a custom font for the login page (Google Fonts)', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_animation">
                                    <?php esc_html_e('Form Animation', 'mbr-login-customiser'); ?>
                                </label>
                            </th>
                            <td>
                                <select id="mbr_custom_login_animation" name="mbr_custom_login_animation">
                                    <option value="none" <?php selected(get_option('mbr_custom_login_animation', 'none'), 'none'); ?>><?php esc_html_e('None', 'mbr-login-customiser'); ?></option>
                                    <option value="fade" <?php selected(get_option('mbr_custom_login_animation', 'none'), 'fade'); ?>><?php esc_html_e('Fade In', 'mbr-login-customiser'); ?></option>
                                    <option value="slide" <?php selected(get_option('mbr_custom_login_animation', 'none'), 'slide'); ?>><?php esc_html_e('Slide Down', 'mbr-login-customiser'); ?></option>
                                    <option value="zoom" <?php selected(get_option('mbr_custom_login_animation', 'none'), 'zoom'); ?>><?php esc_html_e('Zoom In', 'mbr-login-customiser'); ?></option>
                                    <option value="bounce" <?php selected(get_option('mbr_custom_login_animation', 'none'), 'bounce'); ?>><?php esc_html_e('Bounce', 'mbr-login-customiser'); ?></option>
                                </select>
                                <p class="description">
                                    <?php esc_html_e('Animation effect when the login form loads', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_box_shadow">
                                    <?php esc_html_e('Form Shadow', 'mbr-login-customiser'); ?>
                                </label>
                            </th>
                            <td>
                                <select id="mbr_custom_login_box_shadow" name="mbr_custom_login_box_shadow">
                                    <option value="none" <?php selected(get_option('mbr_custom_login_box_shadow', 'medium'), 'none'); ?>><?php esc_html_e('None', 'mbr-login-customiser'); ?></option>
                                    <option value="subtle" <?php selected(get_option('mbr_custom_login_box_shadow', 'medium'), 'subtle'); ?>><?php esc_html_e('Subtle', 'mbr-login-customiser'); ?></option>
                                    <option value="medium" <?php selected(get_option('mbr_custom_login_box_shadow', 'medium'), 'medium'); ?>><?php esc_html_e('Medium', 'mbr-login-customiser'); ?></option>
                                    <option value="strong" <?php selected(get_option('mbr_custom_login_box_shadow', 'medium'), 'strong'); ?>><?php esc_html_e('Strong', 'mbr-login-customiser'); ?></option>
                                    <option value="glow" <?php selected(get_option('mbr_custom_login_box_shadow', 'medium'), 'glow'); ?>><?php esc_html_e('Glow (uses button color)', 'mbr-login-customiser'); ?></option>
                                </select>
                                <p class="description">
                                    <?php esc_html_e('Shadow depth for the login form box', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_footer_text">
                                    <?php esc_html_e('Footer Text', 'mbr-login-customiser'); ?>
                                </label>
                            </th>
                            <td>
                                <textarea id="mbr_custom_login_footer_text" 
                                          name="mbr_custom_login_footer_text" 
                                          rows="3" 
                                          class="large-text"><?php echo esc_textarea(get_option('mbr_custom_login_footer_text', '')); ?></textarea>
                                <p class="description">
                                    <?php esc_html_e('Custom footer text or HTML to display at the bottom of the login page', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                    </table>
                    <?php submit_button(); ?>
                </form>
            <?php elseif ($active_tab === 'security'): // Security tab ?>
                <form method="post" action="options.php">
                    <?php settings_fields('mbr_custom_login_security'); ?>
                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row">
                                <?php esc_html_e('Limit Login Attempts', 'mbr-login-customiser'); ?>
                            </th>
                            <td>
                                <label>
                                    <input type="checkbox"
                                           name="mbr_custom_login_limit_enabled"
                                           value="1"
                                           <?php checked(get_option('mbr_custom_login_limit_enabled', 0), 1); ?>>
                                    <?php esc_html_e('Lock out an IP address after too many failed login attempts', 'mbr-login-customiser'); ?>
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_max_attempts">
                                    <?php esc_html_e('Max Failed Attempts', 'mbr-login-customiser'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="number" min="1" max="100"
                                       id="mbr_custom_login_max_attempts"
                                       name="mbr_custom_login_max_attempts"
                                       value="<?php echo esc_attr(get_option('mbr_custom_login_max_attempts', 5)); ?>"
                                       class="small-text">
                                <p class="description">
                                    <?php esc_html_e('Number of failed attempts allowed before an IP is locked out.', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_attempt_window">
                                    <?php esc_html_e('Attempt Window (minutes)', 'mbr-login-customiser'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="number" min="1" max="1440"
                                       id="mbr_custom_login_attempt_window"
                                       name="mbr_custom_login_attempt_window"
                                       value="<?php echo esc_attr(get_option('mbr_custom_login_attempt_window', 15)); ?>"
                                       class="small-text">
                                <p class="description">
                                    <?php esc_html_e('Failed attempts are counted within this rolling window. Older failures are forgiven.', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_lockout_duration">
                                    <?php esc_html_e('Lockout Duration (minutes)', 'mbr-login-customiser'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="number" min="1" max="10080"
                                       id="mbr_custom_login_lockout_duration"
                                       name="mbr_custom_login_lockout_duration"
                                       value="<?php echo esc_attr(get_option('mbr_custom_login_lockout_duration', 15)); ?>"
                                       class="small-text">
                                <p class="description">
                                    <?php esc_html_e('How long a locked-out IP must wait before it can try again.', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Progressive lockouts', 'mbr-login-customiser'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox"
                                           name="mbr_custom_login_progressive_enabled"
                                           value="1"
                                           <?php checked(get_option('mbr_custom_login_progressive_enabled', 1), 1); ?>>
                                    <?php esc_html_e('Make each repeat lockout for the same IP last longer.', 'mbr-login-customiser'); ?>
                                </label>
                                <p class="description">
                                    <?php esc_html_e('A persistent attacker is locked out for progressively longer each time, up to the maximum below.', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_lockout_multiplier">
                                    <?php esc_html_e('Lockout multiplier', 'mbr-login-customiser'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="number" min="1" max="10"
                                       id="mbr_custom_login_lockout_multiplier"
                                       name="mbr_custom_login_lockout_multiplier"
                                       value="<?php echo esc_attr(get_option('mbr_custom_login_lockout_multiplier', 2)); ?>"
                                       class="small-text">
                                <p class="description">
                                    <?php esc_html_e('Each repeat lockout multiplies the duration by this amount (e.g. 2 gives 15, 30, 60 minutes…).', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_lockout_max">
                                    <?php esc_html_e('Maximum lockout (minutes)', 'mbr-login-customiser'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="number" min="1"
                                       id="mbr_custom_login_lockout_max"
                                       name="mbr_custom_login_lockout_max"
                                       value="<?php echo esc_attr(get_option('mbr_custom_login_lockout_max', 1440)); ?>"
                                       class="small-text">
                                <p class="description">
                                    <?php esc_html_e('Upper limit on a single lockout, however many times the IP has offended. Default 1440 (24 hours).', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_offense_memory">
                                    <?php esc_html_e('Offence memory (hours)', 'mbr-login-customiser'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="number" min="1" max="8760"
                                       id="mbr_custom_login_offense_memory"
                                       name="mbr_custom_login_offense_memory"
                                       value="<?php echo esc_attr(get_option('mbr_custom_login_offense_memory', 24)); ?>"
                                       class="small-text">
                                <p class="description">
                                    <?php esc_html_e('How long an IP is remembered for escalation. After this quiet period its offence count resets. Default 24.', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <?php esc_html_e('Behind a Proxy / CDN', 'mbr-login-customiser'); ?>
                            </th>
                            <td>
                                <label>
                                    <input type="checkbox"
                                           name="mbr_custom_login_behind_proxy"
                                           value="1"
                                           <?php checked(get_option('mbr_custom_login_behind_proxy', 0), 1); ?>>
                                    <?php esc_html_e('My site sits behind Cloudflare or another reverse proxy', 'mbr-login-customiser'); ?>
                                </label>
                                <p class="description">
                                    <?php esc_html_e('Enable this so the real visitor IP is read from proxy headers instead of the proxy\'s own address. Leave off if you are not behind a proxy, as these headers can otherwise be spoofed.', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_proxy_header">
                                    <?php esc_html_e('Trusted IP Header', 'mbr-login-customiser'); ?>
                                </label>
                            </th>
                            <td>
                                <?php $proxy_header = get_option('mbr_custom_login_proxy_header', 'HTTP_CF_CONNECTING_IP'); ?>
                                <select id="mbr_custom_login_proxy_header" name="mbr_custom_login_proxy_header">
                                    <option value="HTTP_CF_CONNECTING_IP" <?php selected($proxy_header, 'HTTP_CF_CONNECTING_IP'); ?>>Cloudflare (CF-Connecting-IP)</option>
                                    <option value="HTTP_TRUE_CLIENT_IP" <?php selected($proxy_header, 'HTTP_TRUE_CLIENT_IP'); ?>>Akamai / Cloudflare Enterprise (True-Client-IP)</option>
                                    <option value="HTTP_X_REAL_IP" <?php selected($proxy_header, 'HTTP_X_REAL_IP'); ?>>nginx (X-Real-IP)</option>
                                    <option value="HTTP_X_FORWARDED_FOR" <?php selected($proxy_header, 'HTTP_X_FORWARDED_FOR'); ?>>Generic (X-Forwarded-For)</option>
                                </select>
                                <p class="description">
                                    <?php esc_html_e('Only used when the proxy/CDN option above is enabled. Choose the single header your proxy sets, and make sure your origin server only accepts traffic from that proxy, otherwise this header can be spoofed.', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_whitelist_ips">
                                    <?php esc_html_e('Trusted IPs (whitelist)', 'mbr-login-customiser'); ?>
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
                                        /* translators: %s: the visitor's current IP address, wrapped in a <code> element. */
                                        esc_html__('One IP or CIDR range per line (e.g. 203.0.113.5 or 203.0.113.0/24). Trusted IPs are never locked out or blocked. Your current IP: %s', 'mbr-login-customiser'),
                                        '<code>' . esc_html(MBR_Login_Security::get_client_ip()) . '</code>'
                                    );
                                    ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="mbr_custom_login_blacklist_ips">
                                    <?php esc_html_e('Blocked IPs (blacklist)', 'mbr-login-customiser'); ?>
                                </label>
                            </th>
                            <td>
                                <textarea id="mbr_custom_login_blacklist_ips"
                                          name="mbr_custom_login_blacklist_ips"
                                          rows="4"
                                          class="large-text code"><?php echo esc_textarea(get_option('mbr_custom_login_blacklist_ips', '')); ?></textarea>
                                <p class="description">
                                    <?php esc_html_e('One IP or CIDR range per line. These addresses are blocked from signing in. Trusted IPs above always take precedence.', 'mbr-login-customiser'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Exclusive access', 'mbr-login-customiser'); ?></th>
                            <td>
                                <?php
                                $current_ip      = MBR_Login_Security::get_client_ip();
                                $whitelist_only  = (bool) get_option('mbr_custom_login_whitelist_only', 0);
                                $whitelist_empty = trim((string) get_option('mbr_custom_login_whitelist_ips', '')) === '';
                                $current_listed  = MBR_Login_Access::is_whitelisted($current_ip);
                                ?>
                                <label>
                                    <input type="checkbox"
                                           name="mbr_custom_login_whitelist_only"
                                           value="1"
                                           <?php checked($whitelist_only, 1); ?>>
                                    <?php esc_html_e('Allow login only from trusted IPs above (block everyone else).', 'mbr-login-customiser'); ?>
                                </label>
                                <p class="description">
                                    <?php esc_html_e('Only takes effect while the trusted IP list is not empty, so an empty list cannot lock everyone out.', 'mbr-login-customiser'); ?>
                                </p>
                                <?php if ($whitelist_only && !$whitelist_empty && !$current_listed): ?>
                                    <p class="description" style="color:#b32d2e;font-weight:600;">
                                        <?php
                                        printf(
                                            /* translators: %s: the visitor's current IP address, wrapped in a <code> element. */
                                            esc_html__('Warning: your current IP (%s) is not in the trusted list. Add it before relying on this, or you may lock yourself out.', 'mbr-login-customiser'),
                                            '<code>' . esc_html($current_ip) . '</code>'
                                        );
                                        ?>
                                    </p>
                                <?php endif; ?>
                            </td>
                        </tr>
                    </table>
                    <?php submit_button(); ?>
                </form>

                <?php
                // Active lockouts table.
                $data = $this->security->get_attempt_data();
                $now  = time();
                $locked = array();
                foreach ($data as $key => $rec) {
                    if (!empty($rec['lock_until']) && $rec['lock_until'] > $now) {
                        $locked[$key] = $rec;
                    }
                }
                ?>
                <h2><?php esc_html_e('Currently Locked Out', 'mbr-login-customiser'); ?></h2>
                <?php if (empty($locked)): ?>
                    <p><?php esc_html_e('No IP addresses are currently locked out.', 'mbr-login-customiser'); ?></p>
                <?php else: ?>
                    <table class="widefat striped" style="max-width:640px;">
                        <thead>
                            <tr>
                                <th><?php esc_html_e('IP Address', 'mbr-login-customiser'); ?></th>
                                <th><?php esc_html_e('Offences', 'mbr-login-customiser'); ?></th>
                                <th><?php esc_html_e('Unlocks In', 'mbr-login-customiser'); ?></th>
                                <th><?php esc_html_e('Action', 'mbr-login-customiser'); ?></th>
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
                                    <td><code><?php echo esc_html(isset($rec['ip']) ? $rec['ip'] : __('unknown', 'mbr-login-customiser')); ?></code></td>
                                    <td><?php echo esc_html(isset($rec['offenses']) ? (int) $rec['offenses'] : 1); ?></td>
                                    <td>
                                        <?php
                                        /* translators: %d: number of minutes remaining until the IP lockout expires. */
                                        printf(esc_html(_n('%d minute', '%d minutes', $mins, 'mbr-login-customiser')), (int) $mins);
                                        ?>
                                    </td>
                                    <td><a href="<?php echo esc_url($unlock_url); ?>" class="button button-small"><?php esc_html_e('Unlock', 'mbr-login-customiser'); ?></a></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    <p>
                        <a href="<?php echo esc_url(wp_nonce_url(admin_url('options-general.php?page=mbr-custom-login&tab=security&mbr_unlock=all'), 'mbr_unlock')); ?>"
                           class="button"><?php esc_html_e('Clear All Lockouts', 'mbr-login-customiser'); ?></a>
                    </p>
                <?php endif; ?>

            <?php elseif ($active_tab === 'logs'): ?>

                <?php $this->render_logs_tab(); ?>

            <?php elseif ($active_tab === 'redirects'): ?>

                <?php $this->render_redirects_tab(); ?>

            <?php elseif ($active_tab === 'schedule'): ?>

                <?php $this->render_schedule_tab(); ?>

            <?php elseif ($active_tab === '2fa'): ?>

                <?php $this->render_2fa_tab(); ?>

            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * Render the Logs tab: settings form plus the attempt table.
     */
    private function render_logs_tab() {
        $allowed_events = array('', 'failed', 'success', 'lockout', 'blocked');
        $event_filter   = isset($_GET['log_event']) ? sanitize_text_field(wp_unslash($_GET['log_event'])) : '';
        if (!in_array($event_filter, $allowed_events, true)) {
            $event_filter = '';
        }

        $per_page = 50;
        $paged    = isset($_GET['log_page']) ? max(1, absint($_GET['log_page'])) : 1;
        $offset   = ($paged - 1) * $per_page;

        $total   = $this->log->count_entries($event_filter);
        $entries = $this->log->get_entries($per_page, $offset, $event_filter);
        $pages   = max(1, (int) ceil($total / $per_page));

        $enabled   = (bool) get_option('mbr_custom_login_log_enabled', 1);
        $retention = (int) get_option('mbr_custom_login_log_retention_days', 30);
        ?>
        <form method="post" action="options.php" style="margin-top:1em;">
            <?php settings_fields('mbr_custom_login_logging'); ?>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><?php esc_html_e('Enable logging', 'mbr-login-customiser'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="mbr_custom_login_log_enabled" value="1" <?php checked($enabled); ?>>
                            <?php esc_html_e('Record login attempts (failed, successful and lockouts).', 'mbr-login-customiser'); ?>
                        </label>
                        <p class="description"><?php esc_html_e('Logged data includes IP addresses. Entries are pruned automatically after the retention period below.', 'mbr-login-customiser'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="mbr_custom_login_log_retention_days"><?php esc_html_e('Retention (days)', 'mbr-login-customiser'); ?></label></th>
                    <td>
                        <input type="number" min="1" max="3650" id="mbr_custom_login_log_retention_days" name="mbr_custom_login_log_retention_days" value="<?php echo esc_attr($retention); ?>" class="small-text">
                        <p class="description"><?php esc_html_e('Entries older than this are deleted by a daily cleanup.', 'mbr-login-customiser'); ?></p>
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>

        <hr>

        <h2><?php esc_html_e('Recent attempts', 'mbr-login-customiser'); ?></h2>

        <?php
        // Filter links.
        $base = admin_url('options-general.php?page=mbr-custom-login&tab=logs');
        $filters = array(
            ''        => __('All', 'mbr-login-customiser'),
            'failed'  => __('Failed', 'mbr-login-customiser'),
            'success' => __('Success', 'mbr-login-customiser'),
            'lockout' => __('Lockout', 'mbr-login-customiser'),
            'blocked' => __('Blocked', 'mbr-login-customiser'),
        );
        ?>
        <ul class="subsubsub">
            <?php $first = true; foreach ($filters as $ev => $label): ?>
                <li>
                    <?php if (!$first) echo ' | '; $first = false; ?>
                    <a href="<?php echo esc_url($ev === '' ? $base : add_query_arg('log_event', $ev, $base)); ?>"
                       class="<?php echo $event_filter === $ev ? 'current' : ''; ?>">
                        <?php echo esc_html($label); ?>
                    </a>
                </li>
            <?php endforeach; ?>
        </ul>

        <p>
            <?php
            /* translators: %d: total number of matching log entries */
            echo esc_html(sprintf(_n('%d entry', '%d entries', $total, 'mbr-login-customiser'), $total));
            ?>
            &nbsp;
            <a href="<?php echo esc_url(wp_nonce_url(add_query_arg('mbr_clear_log', '1', $base), 'mbr_clear_log')); ?>"
               class="button"
               onclick="return confirm('<?php echo esc_js(__('Clear the entire log? This cannot be undone.', 'mbr-login-customiser')); ?>');">
                <?php esc_html_e('Clear log', 'mbr-login-customiser'); ?>
            </a>
        </p>

        <table class="widefat striped">
            <thead>
                <tr>
                    <th><?php esc_html_e('Time', 'mbr-login-customiser'); ?></th>
                    <th><?php esc_html_e('Event', 'mbr-login-customiser'); ?></th>
                    <th><?php esc_html_e('Username', 'mbr-login-customiser'); ?></th>
                    <th><?php esc_html_e('IP address', 'mbr-login-customiser'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($entries)): ?>
                    <tr><td colspan="4"><?php esc_html_e('No log entries.', 'mbr-login-customiser'); ?></td></tr>
                <?php else: ?>
                    <?php foreach ($entries as $row): ?>
                        <?php
                        $local_time = get_date_from_gmt($row->log_time, 'Y-m-d H:i:s');
                        $colours = array('failed' => '#b32d2e', 'success' => '#1a7f37', 'lockout' => '#996800', 'blocked' => '#8a2be2');
                        $colour  = isset($colours[$row->event]) ? $colours[$row->event] : '#50575e';
                        ?>
                        <tr>
                            <td><?php echo esc_html($local_time); ?></td>
                            <td><span style="display:inline-block;padding:1px 8px;border-radius:3px;color:#fff;background:<?php echo esc_attr($colour); ?>;"><?php echo esc_html($row->event); ?></span></td>
                            <td><?php echo esc_html($row->username); ?></td>
                            <td><?php echo esc_html($row->ip); ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>

        <?php if ($pages > 1): ?>
            <p class="tablenav-pages" style="margin-top:1em;">
                <?php
                $page_base = $event_filter === '' ? $base : add_query_arg('log_event', $event_filter, $base);
                if ($paged > 1) {
                    echo '<a class="button" href="' . esc_url(add_query_arg('log_page', $paged - 1, $page_base)) . '">&laquo; ' . esc_html__('Previous', 'mbr-login-customiser') . '</a> ';
                }
                /* translators: 1: current page number, 2: total number of pages */
                echo '<span style="margin:0 8px;">' . esc_html(sprintf(__('Page %1$d of %2$d', 'mbr-login-customiser'), $paged, $pages)) . '</span>';
                if ($paged < $pages) {
                    echo '<a class="button" href="' . esc_url(add_query_arg('log_page', $paged + 1, $page_base)) . '">' . esc_html__('Next', 'mbr-login-customiser') . ' &raquo;</a>';
                }
                ?>
            </p>
        <?php endif; ?>
        <?php
    }

    /**
     * Render the Redirects tab.
     */
    private function render_redirects_tab() {
        $enabled = (bool) get_option('mbr_custom_login_redirect_enabled', 1);
        $default = (string) get_option('mbr_custom_login_redirect_default', '');
        $logout  = (string) get_option('mbr_custom_login_logout_redirect', '');
        $rules   = get_option('mbr_custom_login_redirect_rules', array());
        if (!is_array($rules)) {
            $rules = array();
        }
        // Always render at least one (blank) row so the feature is usable
        // without JavaScript.
        $render_rules = $rules;
        $render_rules[] = array('type' => 'role', 'value' => '', 'url' => '');

        $roles = function_exists('get_editable_roles') ? get_editable_roles() : array();
        ?>
        <form method="post" action="options.php" style="margin-top:1em;">
            <?php settings_fields('mbr_custom_login_redirects'); ?>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><?php esc_html_e('Enable redirects', 'mbr-login-customiser'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="mbr_custom_login_redirect_enabled" value="1" <?php checked($enabled); ?>>
                            <?php esc_html_e('Apply the custom login and logout redirects below.', 'mbr-login-customiser'); ?>
                        </label>
                    </td>
                </tr>
            </table>

            <h2><?php esc_html_e('Login redirect rules', 'mbr-login-customiser'); ?></h2>
            <p class="description">
                <?php esc_html_e('Rules are checked top to bottom. Specific-user rules always win over role rules. URLs may be a full address or a site path such as /dashboard.', 'mbr-login-customiser'); ?>
            </p>

            <table class="widefat striped" style="max-width:860px;margin-bottom:1em;">
                <thead>
                    <tr>
                        <th style="width:160px;"><?php esc_html_e('Match', 'mbr-login-customiser'); ?></th>
                        <th><?php esc_html_e('Role slug or username', 'mbr-login-customiser'); ?></th>
                        <th><?php esc_html_e('Redirect to', 'mbr-login-customiser'); ?></th>
                        <th style="width:70px;"></th>
                    </tr>
                </thead>
                <tbody id="mbr-redirect-rows">
                    <?php foreach ($render_rules as $i => $rule):
                        $type  = (isset($rule['type']) && 'user' === $rule['type']) ? 'user' : 'role';
                        $value = isset($rule['value']) ? $rule['value'] : '';
                        $rurl  = isset($rule['url']) ? $rule['url'] : '';
                    ?>
                        <tr class="mbr-redirect-row">
                            <td>
                                <select name="mbr_custom_login_redirect_rules[<?php echo (int) $i; ?>][type]">
                                    <option value="role" <?php selected($type, 'role'); ?>><?php esc_html_e('Role', 'mbr-login-customiser'); ?></option>
                                    <option value="user" <?php selected($type, 'user'); ?>><?php esc_html_e('Specific user', 'mbr-login-customiser'); ?></option>
                                </select>
                            </td>
                            <td>
                                <input type="text"
                                       class="regular-text"
                                       name="mbr_custom_login_redirect_rules[<?php echo (int) $i; ?>][value]"
                                       value="<?php echo esc_attr($value); ?>"
                                       placeholder="<?php esc_attr_e('e.g. subscriber or jbloggs', 'mbr-login-customiser'); ?>">
                            </td>
                            <td>
                                <input type="text"
                                       class="regular-text"
                                       name="mbr_custom_login_redirect_rules[<?php echo (int) $i; ?>][url]"
                                       value="<?php echo esc_attr($rurl); ?>"
                                       placeholder="/dashboard">
                            </td>
                            <td>
                                <button type="button" class="button button-small mbr-remove-redirect"><?php esc_html_e('Remove', 'mbr-login-customiser'); ?></button>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <p>
                <button type="button" class="button" id="mbr-add-redirect"><?php esc_html_e('Add rule', 'mbr-login-customiser'); ?></button>
            </p>

            <?php if (!empty($roles)): ?>
                <p class="description">
                    <?php
                    printf(
                        /* translators: %s: comma-separated list of available role slugs */
                        esc_html__('Available role slugs: %s', 'mbr-login-customiser'),
                        '<code>' . esc_html(implode('</code>, <code>', array_keys($roles))) . '</code>'
                    );
                    ?>
                </p>
            <?php endif; ?>

            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><label for="mbr_custom_login_redirect_default"><?php esc_html_e('Default login redirect', 'mbr-login-customiser'); ?></label></th>
                    <td>
                        <input type="text" id="mbr_custom_login_redirect_default" name="mbr_custom_login_redirect_default" value="<?php echo esc_attr($default); ?>" class="regular-text" placeholder="/welcome">
                        <p class="description"><?php esc_html_e('Used when no rule above matches. Leave blank to keep the WordPress default.', 'mbr-login-customiser'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="mbr_custom_login_logout_redirect"><?php esc_html_e('Logout redirect', 'mbr-login-customiser'); ?></label></th>
                    <td>
                        <input type="text" id="mbr_custom_login_logout_redirect" name="mbr_custom_login_logout_redirect" value="<?php echo esc_attr($logout); ?>" class="regular-text" placeholder="/">
                        <p class="description"><?php esc_html_e('Where users land after logging out. Leave blank to keep the WordPress default.', 'mbr-login-customiser'); ?></p>
                    </td>
                </tr>
            </table>

            <?php submit_button(); ?>
        </form>
        <?php
    }

    /**
     * Render the Schedule (time-based access) tab.
     */
    private function render_schedule_tab() {
        $enabled = (bool) get_option('mbr_custom_login_time_enabled', 0);
        $rules   = get_option('mbr_custom_login_time_rules', array());
        if (!is_array($rules)) {
            $rules = array();
        }

        global $wp_locale;
        $fallback = array(
            0 => __('Sunday', 'mbr-login-customiser'),
            1 => __('Monday', 'mbr-login-customiser'),
            2 => __('Tuesday', 'mbr-login-customiser'),
            3 => __('Wednesday', 'mbr-login-customiser'),
            4 => __('Thursday', 'mbr-login-customiser'),
            5 => __('Friday', 'mbr-login-customiser'),
            6 => __('Saturday', 'mbr-login-customiser'),
        );
        $order   = array(1, 2, 3, 4, 5, 6, 0); // Monday first
        $now_str = function_exists('wp_date') ? wp_date('l H:i') : '';
        ?>
        <form method="post" action="options.php" style="margin-top:1em;">
            <?php settings_fields('mbr_custom_login_schedule'); ?>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><?php esc_html_e('Restrict login hours', 'mbr-login-customiser'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="mbr_custom_login_time_enabled" value="1" <?php checked($enabled); ?>>
                            <?php esc_html_e('Only allow logins within the times set below.', 'mbr-login-customiser'); ?>
                        </label>
                        <p class="description">
                            <?php
                            esc_html_e('Uses your site timezone. Whitelisted IPs (Security tab) always bypass the schedule, and this only affects new logins, not existing sessions.', 'mbr-login-customiser');
                            if ($now_str !== '') {
                                echo ' ';
                                printf(
                                    /* translators: %s: current site date/time, e.g. "Monday 14:30" */
                                    esc_html__('Site time now: %s.', 'mbr-login-customiser'),
                                    '<code>' . esc_html($now_str) . '</code>'
                                );
                            }
                            ?>
                        </p>
                    </td>
                </tr>
            </table>

            <table class="widefat striped" style="max-width:560px;">
                <thead>
                    <tr>
                        <th><?php esc_html_e('Day', 'mbr-login-customiser'); ?></th>
                        <th><?php esc_html_e('Allow logins', 'mbr-login-customiser'); ?></th>
                        <th><?php esc_html_e('From', 'mbr-login-customiser'); ?></th>
                        <th><?php esc_html_e('To', 'mbr-login-customiser'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($order as $d):
                        $row     = isset($rules[$d]) && is_array($rules[$d]) ? $rules[$d] : array();
                        $d_on    = !empty($row['enabled']);
                        $d_start = isset($row['start']) ? $row['start'] : '';
                        $d_end   = isset($row['end']) ? $row['end'] : '';
                        $name    = isset($wp_locale) ? $wp_locale->get_weekday($d) : $fallback[$d];
                    ?>
                        <tr>
                            <td><?php echo esc_html($name); ?></td>
                            <td><input type="checkbox" name="mbr_custom_login_time_rules[<?php echo (int) $d; ?>][enabled]" value="1" <?php checked($d_on); ?>></td>
                            <td><input type="time" name="mbr_custom_login_time_rules[<?php echo (int) $d; ?>][start]" value="<?php echo esc_attr($d_start); ?>"></td>
                            <td><input type="time" name="mbr_custom_login_time_rules[<?php echo (int) $d; ?>][end]" value="<?php echo esc_attr($d_end); ?>"></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <p class="description" style="max-width:560px;">
                <?php esc_html_e('Leave From/To blank (or equal) to allow that whole day. A From later than To means an overnight window, e.g. 22:00 to 06:00.', 'mbr-login-customiser'); ?>
            </p>

            <?php submit_button(); ?>
        </form>
        <?php
    }

    /**
     * Render the Two-Factor tab.
     */
    private function render_2fa_tab() {
        $enabled = (bool) get_option('mbr_custom_login_2fa_enabled', 0);
        $count   = $this->twofa->count_enrolled_users();
        $app_pw  = get_option('mbr_custom_login_2fa_app_passwords', 'block');
        ?>
        <form method="post" action="options.php" style="margin-top:1em;">
            <?php settings_fields('mbr_custom_login_2fa'); ?>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><?php esc_html_e('Enable two-factor', 'mbr-login-customiser'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="mbr_custom_login_2fa_enabled" value="1" <?php checked($enabled); ?>>
                            <?php esc_html_e('Allow users to protect their account with an authenticator app (TOTP).', 'mbr-login-customiser'); ?>
                        </label>
                        <p class="description">
                            <?php
                            printf(
                                /* translators: %d: number of users who have enabled two-factor */
                                esc_html(_n('%d user has two-factor enabled.', '%d users have two-factor enabled.', $count, 'mbr-login-customiser')),
                                (int) $count
                            );
                            ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e('Application Passwords', 'mbr-login-customiser'); ?></th>
                    <td>
                        <select name="mbr_custom_login_2fa_app_passwords">
                            <option value="block" <?php selected($app_pw, 'block'); ?>><?php esc_html_e('Disable for users with two-factor (recommended)', 'mbr-login-customiser'); ?></option>
                            <option value="allow" <?php selected($app_pw, 'allow'); ?>><?php esc_html_e('Allow as an API credential for users with two-factor', 'mbr-login-customiser'); ?></option>
                        </select>
                        <p class="description">
                            <?php esc_html_e('Application Passwords authenticate the REST API and apps without a second-factor prompt. Disabling them for two-factor users removes any password-only path that would skip 2FA. Choose "Allow" only if those users rely on API or app integrations.', 'mbr-login-customiser'); ?>
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
                /* translators: %s: a link to the user's own profile page (Users > Profile) */
                esc_html__('Once enabled, each user turns on two-factor from %s by scanning the QR code (or adding the setup key) into an authenticator app and confirming a code. They receive single-use recovery codes for emergencies.', 'mbr-login-customiser'),
                '<a href="' . esc_url(admin_url('profile.php')) . '">' . esc_html__('Users → Profile', 'mbr-login-customiser') . '</a>'
            );
            ?>
        </p>
        <p class="description" style="max-width:680px;">
            <?php esc_html_e('If a user loses access, an administrator can reset their two-factor from that user\'s page under Users. As a last resort, add this line to wp-config.php to disable two-factor everywhere:', 'mbr-login-customiser'); ?>
            <br><code>define('MBR_LOGIN_2FA_DISABLE', true);</code>
        </p>
        <?php
    }
}
