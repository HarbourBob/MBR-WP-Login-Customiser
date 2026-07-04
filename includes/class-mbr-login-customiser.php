<?php
/**
 * Plugin loader / orchestrator.
 *
 * @package MBR_Login_Customiser
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Wires the feature modules together. Kept as the historical
 * MBR_Custom_Login class name so the existing bootstrap entry point is
 * unchanged.
 */
class MBR_Custom_Login {

    private static $instance = null;

    private $url;
    private $appearance;
    private $security;
    private $access;
    private $redirect;
    private $twofa;
    private $passkeys;
    private $alerts;
    private $trusted;
    private $network;
    private $log;
    private $admin;

    /**
     * Get singleton instance.
     */
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Build the modules and register their hooks.
     */
    private function __construct() {
        add_action('plugins_loaded', array($this, 'init'));

        $this->security   = new MBR_Login_Security();
        $this->access     = new MBR_Login_Access();
        $this->redirect   = new MBR_Login_Redirect();
        $this->twofa      = new MBR_Login_2FA();
        $this->passkeys   = new MBR_Login_Passkeys();
        $this->alerts     = new MBR_Login_Alerts();
        $this->trusted    = new MBR_Login_Trusted_Devices();
        $this->network    = new MBR_Login_Network();
        $this->log        = new MBR_Login_Log();
        $this->url        = new MBR_Login_Url();
        $this->appearance = new MBR_Login_Appearance();
        $this->admin      = new MBR_Login_Admin($this->security, $this->log, $this->twofa);

        $this->security->register_hooks();
        $this->access->register_hooks();
        $this->redirect->register_hooks();
        $this->twofa->register_hooks();
        $this->passkeys->register_hooks();
        $this->alerts->register_hooks();
        $this->trusted->register_hooks();
        $this->network->register_hooks();
        $this->log->register_hooks();
        $this->url->register_hooks();
        $this->appearance->register_hooks();
        $this->admin->register_hooks();
    }

    /**
     * Load translations.
     */
    public function init() {
        load_plugin_textdomain('mbr-login-customiser', false, dirname(plugin_basename(MBR_CUSTOM_LOGIN_PLUGIN_FILE)) . '/languages');
    }

    /**
     * Accessor for the security module (used by activation defaults/tests).
     */
    public function security() {
        return $this->security;
    }

    /**
     * Accessor for the log module.
     */
    public function log() {
        return $this->log;
    }

    /**
     * Accessor for the access module.
     */
    public function access() {
        return $this->access;
    }

    /**
     * Accessor for the redirect module.
     */
    public function redirect() {
        return $this->redirect;
    }

    /**
     * Accessor for the 2FA module.
     */
    public function twofa() {
        return $this->twofa;
    }

    /**
     * Accessor for the passkeys module.
     */
    public function passkeys() {
        return $this->passkeys;
    }

    /**
     * Accessor for the alerts module.
     */
    public function alerts() {
        return $this->alerts;
    }

    /**
     * Accessor for the trusted-devices module.
     */
    public function trusted() {
        return $this->trusted;
    }

    /**
     * Accessor for the network module.
     */
    public function network() {
        return $this->network;
    }
}
