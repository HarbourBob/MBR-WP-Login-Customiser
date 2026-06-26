<?php
/**
 * Login page appearance customisation.
 *
 * @package MBR_Login_Customiser
 */

if (!defined('ABSPATH')) {
    exit;
}

class MBR_Login_Appearance {

    /**
     * Register WordPress hooks for this module.
     */
    public function register_hooks() {
        add_action('login_enqueue_scripts', array($this, 'customize_login_page'));
        add_filter('login_headerurl', array($this, 'custom_login_logo_url'));
        add_filter('login_headertext', array($this, 'custom_login_logo_text'));
        add_filter('login_message', array($this, 'custom_login_message'));
        add_filter('login_footer', array($this, 'custom_login_footer'));
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
        // Constrain to a known-good set so nothing arbitrary reaches the CSS
        // context (esc_attr does not neutralise CSS metacharacters like ) ; { }).
        $allowed_directions = array(
            'to bottom', 'to top', 'to right', 'to left',
            'to bottom right', 'to bottom left',
        );
        if (!in_array($custom_bg_gradient_direction, $allowed_directions, true)) {
            $custom_bg_gradient_direction = 'to bottom right';
        }
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
            // Enqueue via the proper API rather than printing a raw <link> tag.
            wp_enqueue_style('mbr-custom-login-google-fonts', $google_fonts_url, array(), MBR_CUSTOM_LOGIN_VERSION);
        }
        
        ?>
        <?php if (!empty($google_fonts_url)): ?>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
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
                    font-family: '<?php echo esc_attr(str_replace('+', ' ', $font_family)); ?>', sans-serif !important;
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
                box-shadow: <?php echo esc_attr($shadow_value); ?> !important;
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
            
            <?php
            // CSS printed inside a <style> element: HTML escaping functions would
            // corrupt valid CSS, so the value is sanitised (tags stripped and any
            // </style> breakout removed) instead.
            echo $this->sanitize_css($custom_css); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            ?>
        </style>
        <?php
    }

    /**
     * Sanitize custom CSS for safe output inside a <style> element.
     *
     * Mirrors MBR_Login_Admin::sanitize_css() (the save-time callback); kept
     * here so the front-end output path has no dependency on the admin module.
     * Keep the two in step if the rules ever change.
     */
    private function sanitize_css($css) {
        // Strip any HTML tags, then neutralise any attempt to break out of the
        // <style> element (e.g. a stray "</style>") so the value is safe to print.
        $css = wp_strip_all_tags((string) $css);
        $css = preg_replace('#</?\s*style#i', '', $css);
        return $css;
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
}
