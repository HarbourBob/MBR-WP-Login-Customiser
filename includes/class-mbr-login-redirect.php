<?php
/**
 * Custom login and logout redirects.
 *
 * Sends users to a chosen destination after login based on a list of
 * user-specific or role-based rules (user rules take precedence), with an
 * optional site-wide default, and an optional single logout destination.
 *
 * Self-contained: hooks only the core login_redirect / logout_redirect filters
 * and reads its own options.
 *
 * @package MBR_Login_Customiser
 */

if (!defined('ABSPATH')) {
    exit;
}

class MBR_Login_Redirect {

    /**
     * Register WordPress hooks for this module.
     */
    public function register_hooks() {
        add_filter('login_redirect', array($this, 'filter_login_redirect'), 10, 3);
        add_filter('logout_redirect', array($this, 'filter_logout_redirect'), 10, 3);
    }

    private function is_enabled() {
        return (bool) get_option('mbr_custom_login_redirect_enabled', 1);
    }

    /**
     * login_redirect filter: choose a destination for the user who just logged
     * in, falling back to whatever WordPress already decided.
     *
     * @param string           $redirect_to
     * @param string           $requested
     * @param WP_User|WP_Error  $user
     * @return string
     */
    public function filter_login_redirect($redirect_to, $requested, $user) {
        if (!$this->is_enabled()) {
            return $redirect_to;
        }
        if (!($user instanceof WP_User) || empty($user->ID)) {
            return $redirect_to;
        }

        $target = $this->resolve_for_user($user);
        return $target !== '' ? $target : $redirect_to;
    }

    /**
     * logout_redirect filter: send everyone to a single destination on logout,
     * if one is configured.
     */
    public function filter_logout_redirect($redirect_to, $requested, $user) {
        if (!$this->is_enabled()) {
            return $redirect_to;
        }
        $url = $this->normalise_url((string) get_option('mbr_custom_login_logout_redirect', ''));
        return $url !== '' ? $url : $redirect_to;
    }

    /**
     * Work out the destination for a user: user rules first, then role rules in
     * list order, then the site-wide default.
     *
     * @param WP_User $user
     * @return string Empty string means "no opinion".
     */
    private function resolve_for_user($user) {
        $rules = get_option('mbr_custom_login_redirect_rules', array());
        if (!is_array($rules)) {
            $rules = array();
        }

        foreach ($rules as $rule) {
            if (isset($rule['type']) && 'user' === $rule['type']
                && $this->user_matches($user, isset($rule['value']) ? $rule['value'] : '')) {
                return $this->normalise_url(isset($rule['url']) ? $rule['url'] : '');
            }
        }

        $roles = (array) $user->roles;
        foreach ($rules as $rule) {
            if (isset($rule['type']) && 'role' === $rule['type']
                && in_array(isset($rule['value']) ? $rule['value'] : '', $roles, true)) {
                return $this->normalise_url(isset($rule['url']) ? $rule['url'] : '');
            }
        }

        return $this->normalise_url((string) get_option('mbr_custom_login_redirect_default', ''));
    }

    /**
     * Does this user match a user-rule value (username or numeric ID)?
     */
    private function user_matches($user, $value) {
        $value = trim((string) $value);
        if ($value === '') {
            return false;
        }
        if (ctype_digit($value) && (int) $value === (int) $user->ID) {
            return true;
        }
        return isset($user->user_login) && 0 === strcasecmp((string) $user->user_login, $value);
    }

    /**
     * Turn a stored path or URL into a full URL. A relative path is resolved
     * against the site home; an absolute http(s) URL is returned unchanged.
     */
    private function normalise_url($url) {
        $url = trim((string) $url);
        if ($url === '') {
            return '';
        }
        if (preg_match('#^https?://#i', $url)) {
            return $url;
        }
        return home_url('/' . ltrim($url, '/'));
    }
}
