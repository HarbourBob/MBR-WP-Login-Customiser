<?php
/**
 * IP access control: whitelist (trusted), blacklist (blocked) and an optional
 * exclusive "whitelist only" mode.
 *
 * This is the access gate that runs on the login authenticate chain. It owns
 * the IP-list matching (exact and CIDR, IPv4 and IPv6) as shared static helpers
 * so other modules (e.g. the lockout check) reuse one implementation.
 *
 * Precedence: a whitelisted IP is always trusted and bypasses every other
 * check. Otherwise a blacklisted IP is blocked, and in exclusive mode any IP
 * not on a non-empty whitelist is blocked.
 *
 * @package MBR_Login_Customiser
 */

if (!defined('ABSPATH')) {
    exit;
}

class MBR_Login_Access {

    /**
     * Set true for the current request when access has blocked the attempt, so
     * the log records a single 'blocked' entry rather than also a 'failed' one.
     *
     * @var bool
     */
    private static $blocked = false;

    /**
     * Register WordPress hooks for this module.
     */
    public function register_hooks() {
        // Priority 95: after WordPress' own credential checks but before the
        // lockout check (99), so a denied IP is stopped regardless of lockout
        // state or whether the credentials were correct.
        add_filter('authenticate', array($this, 'check_ip_access'), 95, 3);
        // Priority 96: time-of-day schedule, after the IP gate.
        add_filter('authenticate', array($this, 'check_time_access'), 96, 3);
    }

    /* ---------------------------------------------------------------------
     * Option readers
     * ------------------------------------------------------------------ */

    public static function whitelist() {
        return (string) get_option('mbr_custom_login_whitelist_ips', '');
    }

    public static function blacklist() {
        $site = (string) get_option('mbr_custom_login_blacklist_ips', '');
        // On multisite, a network-wide blacklist applies to every site too.
        $network = (string) MBR_Login_Options::network_get('mbr_custom_login_network_blacklist', '');
        $combined = trim($site . "\n" . $network);
        return $combined;
    }

    public static function is_whitelisted($ip) {
        return self::ip_in_list($ip, self::whitelist());
    }

    public static function is_blacklisted($ip) {
        return self::ip_in_list($ip, self::blacklist());
    }

    /**
     * Exclusive mode is only in force when explicitly enabled AND the whitelist
     * is non-empty, so an empty list can never lock everyone out.
     */
    public static function is_exclusive_mode() {
        return (bool) get_option('mbr_custom_login_whitelist_only', 0) && trim(self::whitelist()) !== '';
    }

    /**
     * Did the access gate block the current request?
     */
    public static function was_blocked() {
        return self::$blocked;
    }

    /* ---------------------------------------------------------------------
     * The gate
     * ------------------------------------------------------------------ */

    /**
     * authenticate filter: deny blacklisted IPs (and, in exclusive mode, any IP
     * not whitelisted). Whitelisted IPs always pass.
     *
     * @param WP_User|WP_Error|null $user
     * @param string                $username
     * @param string                $password
     * @return WP_User|WP_Error|null
     */
    public function check_ip_access($user, $username, $password) {
        // Ignore empty probes (e.g. an empty form submit).
        if (empty($username) && empty($password)) {
            return $user;
        }

        $ip = MBR_Login_Security::get_client_ip();

        // Trusted IPs bypass every other check.
        if (self::is_whitelisted($ip)) {
            return $user;
        }

        if (self::is_blacklisted($ip)) {
            return $this->deny($ip, $username);
        }

        if (self::is_exclusive_mode()) {
            // Not whitelisted (checked above) and exclusive mode is on.
            return $this->deny($ip, $username);
        }

        return $user;
    }

    /**
     * authenticate filter (priority 96): block logins outside the permitted
     * weekly schedule. Whitelisted IPs always pass.
     *
     * @param WP_User|WP_Error|null $user
     * @param string                $username
     * @param string                $password
     * @return WP_User|WP_Error|null
     */
    public function check_time_access($user, $username, $password) {
        if (empty($username) && empty($password)) {
            return $user;
        }
        // An earlier check already denied this request; don't double-log.
        if (self::$blocked) {
            return $user;
        }
        if (!get_option('mbr_custom_login_time_enabled', 0)) {
            return $user;
        }

        $ip = MBR_Login_Security::get_client_ip();
        if (self::is_whitelisted($ip)) {
            return $user;
        }

        if (!$this->is_within_allowed_hours()) {
            return $this->deny(
                $ip,
                $username,
                __('<strong>Access denied.</strong> Logins are not permitted at this time.', 'mbr-login-customiser')
            );
        }

        return $user;
    }

    /**
     * Is the current site-local time inside the permitted window for today?
     */
    private function is_within_allowed_hours() {
        $rules = get_option('mbr_custom_login_time_rules', array());
        if (!is_array($rules)) {
            return true; // misconfigured: fail open rather than lock everyone out
        }

        list($day, $now_min) = $this->local_day_and_minute();

        if (empty($rules[$day]) || empty($rules[$day]['enabled'])) {
            return false; // logins not permitted on this day
        }

        $start = $this->hm_to_min(isset($rules[$day]['start']) ? $rules[$day]['start'] : '');
        $end   = $this->hm_to_min(isset($rules[$day]['end']) ? $rules[$day]['end'] : '');

        // Incomplete or all-day (start == end): the whole day is permitted.
        if (null === $start || null === $end || $start === $end) {
            return true;
        }

        if ($start < $end) {
            return ($now_min >= $start && $now_min < $end);
        }
        // Overnight window, e.g. 22:00–06:00.
        return ($now_min >= $start || $now_min < $end);
    }

    /**
     * Current weekday (0=Sun..6=Sat) and minutes-since-midnight in the site's
     * timezone. Uses wp_date() (DST-aware) where available.
     *
     * @return array{0:int,1:int}
     */
    private function local_day_and_minute() {
        if (function_exists('wp_date')) {
            $day  = (int) wp_date('w');
            $mins = ((int) wp_date('G') * 60) + (int) wp_date('i');
        } else {
            $day  = (int) current_time('w');
            $mins = ((int) current_time('G') * 60) + (int) current_time('i');
        }
        return array($day, $mins);
    }

    /**
     * Parse an 'HH:MM' string to minutes since midnight, or null if invalid.
     */
    private function hm_to_min($hm) {
        if (!preg_match('/^(\d{1,2}):(\d{2})$/', trim((string) $hm), $m)) {
            return null;
        }
        $h = (int) $m[1];
        $i = (int) $m[2];
        if ($h > 23 || $i > 59) {
            return null;
        }
        return ($h * 60) + $i;
    }

    /**
     * Record the block and return a neutral error.
     */
    private function deny($ip, $username, $message = null) {
        self::$blocked = true;

        /**
         * Fires when the access gate blocks a login attempt. The log module
         * listens for this to record a 'blocked' event.
         *
         * @param string $ip       The (already resolved) client IP.
         * @param string $username The submitted username.
         */
        do_action('mbr_login_customiser_blocked', $ip, $username);

        if (null === $message) {
            $message = __('<strong>Access denied.</strong> Your IP address is not permitted to sign in.', 'mbr-login-customiser');
        }

        return new WP_Error('mbr_login_blocked', $message);
    }

    /* ---------------------------------------------------------------------
     * Matching (shared)
     * ------------------------------------------------------------------ */

    /**
     * Is $ip present in a newline-separated list of exact IPs and/or CIDR
     * ranges?
     */
    public static function ip_in_list($ip, $list_string) {
        $ip = (string) $ip;
        if ($ip === '' || (string) $list_string === '') {
            return false;
        }

        $entries = preg_split('/[\r\n]+/', (string) $list_string);
        foreach ($entries as $entry) {
            $entry = trim($entry);
            if ($entry === '') {
                continue;
            }
            if (strpos($entry, '/') !== false) {
                if (self::ip_in_cidr($ip, $entry)) {
                    return true;
                }
            } elseif ($entry === $ip) {
                return true;
            }
        }
        return false;
    }

    /**
     * Binary CIDR match for IPv4 or IPv6. Returns false on any malformed input
     * or cross-family comparison.
     */
    private static function ip_in_cidr($ip, $cidr) {
        $parts = explode('/', $cidr, 2);
        if (count($parts) !== 2) {
            return false;
        }
        list($subnet, $bits) = $parts;
        if (!is_numeric($bits)) {
            return false;
        }
        $bits = (int) $bits;

        $ip_bin     = @inet_pton($ip);
        $subnet_bin = @inet_pton($subnet);
        if (false === $ip_bin || false === $subnet_bin) {
            return false;
        }
        // Same address family only (4 bytes v4, 16 bytes v6).
        if (strlen($ip_bin) !== strlen($subnet_bin)) {
            return false;
        }
        $max_bits = strlen($ip_bin) * 8;
        if ($bits < 0 || $bits > $max_bits) {
            return false;
        }

        $whole = intdiv($bits, 8);
        $rem   = $bits % 8;

        if ($whole > 0 && substr($ip_bin, 0, $whole) !== substr($subnet_bin, 0, $whole)) {
            return false;
        }
        if ($rem > 0) {
            $mask = chr((0xff << (8 - $rem)) & 0xff);
            if ((ord($ip_bin[$whole]) & ord($mask)) !== (ord($subnet_bin[$whole]) & ord($mask))) {
                return false;
            }
        }
        return true;
    }
}
