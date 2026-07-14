<?php
/**
 * Login attempt logging.
 *
 * Owns the mbr_login_log table: schema install/upgrade, recording, the query
 * API used by the admin viewer, and retention pruning. It is a low-level store
 * with no dependency on the other feature modules; the security module feeds it
 * lockout events through the 'mbr_login_customiser_lockout' action.
 *
 * @package MBR_Login_Customiser
 */

if (!defined('ABSPATH')) {
    exit;
}

class MBR_Login_Log {

    /**
     * Bump when the table schema changes so existing installs upgrade on load.
     */
    const DB_VERSION = '1';

    const DB_VERSION_OPTION = 'mbr_custom_login_db_version';

    /**
     * Daily cron hook that prunes old rows.
     */
    const PRUNE_HOOK = 'mbr_custom_login_log_prune';

    /**
     * Hard ceiling on stored rows, enforced by the pruner as a safety net so a
     * sustained attack cannot grow the table without bound between cron runs.
     */
    const MAX_ROWS = 10000;

    /**
     * Register WordPress hooks for this module.
     */
    public function register_hooks() {
        add_action('wp_login_failed', array($this, 'log_failed'), 20, 1);
        add_action('wp_login', array($this, 'log_success'), 20, 2);
        add_action('mbr_login_customiser_lockout', array($this, 'log_lockout'), 10, 2);
        add_action('mbr_login_customiser_blocked', array($this, 'log_blocked'), 10, 2);
        add_action('mbr_login_customiser_firewall', array($this, 'log_firewall'), 10, 2);
        add_action('admin_init', array($this, 'maybe_upgrade'));
        add_action(self::PRUNE_HOOK, array($this, 'prune'));
    }

    /**
     * Fully-qualified table name.
     */
    public function table_name() {
        global $wpdb;
        return $wpdb->prefix . 'mbr_login_log';
    }

    /**
     * Is logging switched on?
     */
    public function is_enabled() {
        return (bool) get_option('mbr_custom_login_log_enabled', 1);
    }

    /* ---------------------------------------------------------------------
     * Schema
     * ------------------------------------------------------------------ */

    /**
     * Create or update the table. Safe to run repeatedly (dbDelta).
     */
    public function install() {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $table   = $this->table_name();
        $charset = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            log_time DATETIME NOT NULL,
            ip VARCHAR(45) NOT NULL DEFAULT '',
            username VARCHAR(180) NOT NULL DEFAULT '',
            event VARCHAR(20) NOT NULL DEFAULT '',
            user_id BIGINT(20) UNSIGNED NULL DEFAULT NULL,
            PRIMARY KEY  (id),
            KEY log_time (log_time),
            KEY ip (ip),
            KEY event (event)
        ) {$charset};";

        dbDelta($sql);
        update_option(self::DB_VERSION_OPTION, self::DB_VERSION);
    }

    /**
     * Ensure the table exists/upgrades on a normal load (installs that update
     * via the updater never fire the activation hook) and that the prune cron
     * is scheduled.
     */
    public function maybe_upgrade() {
        if (get_option(self::DB_VERSION_OPTION) !== self::DB_VERSION) {
            $this->install();
        }
        if (!wp_next_scheduled(self::PRUNE_HOOK)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::PRUNE_HOOK);
        }
    }

    /* ---------------------------------------------------------------------
     * Recording
     * ------------------------------------------------------------------ */

    /**
     * Insert a single log row (no-op when logging is disabled).
     */
    public function record($event, $ip, $username, $user_id = null) {
        if (!$this->is_enabled()) {
            return;
        }

        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->insert(
            $this->table_name(),
            array(
                'log_time' => current_time('mysql', true), // store as GMT
                'ip'       => substr((string) $ip, 0, 45),
                'username' => substr(sanitize_text_field((string) $username), 0, 180),
                'event'    => substr((string) $event, 0, 20),
                'user_id'  => $user_id ? (int) $user_id : null,
            ),
            array('%s', '%s', '%s', '%s', '%d')
        );

        // Cheap, occasional cap enforcement so a flood cannot run away between
        // daily prunes. ~1% of inserts pay the cost.
        if (1 === wp_rand(1, 100)) {
            $this->enforce_cap();
        }
    }

    /**
     * wp_login_failed handler.
     */
    public function log_failed($username) {
        // If the access gate already blocked this request, it has recorded a
        // 'blocked' entry; don't also record the failed attempt WordPress fires.
        if (class_exists('MBR_Login_Access') && MBR_Login_Access::was_blocked()) {
            return;
        }
        $this->record('failed', MBR_Login_Security::get_client_ip(), $username);
    }

    /**
     * mbr_login_customiser_blocked handler (IP is supplied by the caller).
     */
    public function log_blocked($ip, $username) {
        $this->record('blocked', $ip, $username);
    }

    /**
     * mbr_login_customiser_firewall handler.
     */
    public function log_firewall($ip, $username) {
        $this->record('firewall', $ip, $username);
    }

    /**
     * wp_login handler.
     */
    public function log_success($user_login, $user = null) {
        $user_id = (is_object($user) && isset($user->ID)) ? (int) $user->ID : null;
        $this->record('success', MBR_Login_Security::get_client_ip(), $user_login, $user_id);
    }

    /**
     * mbr_login_customiser_lockout handler (IP is supplied by the caller).
     */
    public function log_lockout($ip, $username) {
        $this->record('lockout', $ip, $username);
    }

    /* ---------------------------------------------------------------------
     * Querying (admin viewer)
     * ------------------------------------------------------------------ */

    /**
     * Count rows, optionally filtered by event type.
     */
    public function count_entries($event = '') {
        global $wpdb;
        $table = $this->table_name();
        if ($event !== '') {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            return (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$table} WHERE event = %s", $event));
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table}");
    }

    /**
     * Fetch a page of rows (newest first), optionally filtered by event type.
     */
    public function get_entries($limit, $offset = 0, $event = '') {
        global $wpdb;
        $table  = $this->table_name();
        $limit  = max(1, (int) $limit);
        $offset = max(0, (int) $offset);

        if ($event !== '') {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            return $wpdb->get_results($wpdb->prepare(
                "SELECT * FROM {$table} WHERE event = %s ORDER BY id DESC LIMIT %d OFFSET %d",
                $event,
                $limit,
                $offset
            ));
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table} ORDER BY id DESC LIMIT %d OFFSET %d",
            $limit,
            $offset
        ));
    }

    /**
     * Empty the log.
     */
    public function clear() {
        global $wpdb;
        $table = $this->table_name();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
        $wpdb->query("TRUNCATE TABLE {$table}");
    }

    /* ---------------------------------------------------------------------
     * Retention
     * ------------------------------------------------------------------ */

    /**
     * Daily cron: drop rows older than the retention window, then cap.
     */
    public function prune() {
        global $wpdb;
        $table  = $this->table_name();
        $days   = (int) get_option('mbr_custom_login_log_retention_days', 30);
        $days   = max(1, min(3650, $days));
        $cutoff = gmdate('Y-m-d H:i:s', time() - ($days * DAY_IN_SECONDS));

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE log_time < %s", $cutoff));

        $this->enforce_cap();
    }

    /**
     * Trim the oldest rows beyond MAX_ROWS.
     */
    private function enforce_cap() {
        global $wpdb;
        $table = $this->table_name();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $count = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table}");
        if ($count > self::MAX_ROWS) {
            $remove = $count - self::MAX_ROWS;
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query($wpdb->prepare("DELETE FROM {$table} ORDER BY id ASC LIMIT %d", $remove));
        }
    }
}
