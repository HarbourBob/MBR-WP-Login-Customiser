<?php
/**
 * Option access wrapper.
 *
 * @package MBR_Login_Customiser
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Thin wrapper around the WordPress options API.
 *
 * Every plugin setting flows (or will flow) through here so that, when network
 * support lands, a single class decides whether a value lives in the per-site
 * options table or the network options table. For now it proxies straight to
 * the standard functions, so behaviour is identical to direct get_option()
 * calls.
 */
class MBR_Login_Options {

    /**
     * Read a plugin option.
     */
    public static function get($key, $default = false) {
        return get_option($key, $default);
    }

    /**
     * Write a plugin option. Plugin data is never autoloaded by default.
     */
    public static function update($key, $value, $autoload = false) {
        return update_option($key, $value, $autoload);
    }

    /**
     * Delete a plugin option.
     */
    public static function delete($key) {
        return delete_option($key);
    }

    /* ---------------------------------------------------------------------
     * Network (multisite) options.
     *
     * Stored network-wide via the site-option API. On single-site installs
     * these fall back to the normal options table, and since the plugin never
     * writes network options outside the Network Admin screen, they simply read
     * back the default — so single-site behaviour is unchanged.
     * ------------------------------------------------------------------ */

    public static function network_get($key, $default = false) {
        return get_site_option($key, $default);
    }

    public static function network_update($key, $value) {
        return update_site_option($key, $value);
    }

    public static function network_delete($key) {
        return delete_site_option($key);
    }
}
