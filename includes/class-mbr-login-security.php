<?php
/**
 * Login attempt limiting, IP handling and lockouts.
 *
 * @package MBR_Login_Customiser
 */

if (!defined('ABSPATH')) {
    exit;
}

class MBR_Login_Security {

    /**
     * Option key holding per-IP attempt/lockout data.
     */
    const ATTEMPT_OPTION = 'mbr_custom_login_attempt_data';

    /**
     * Hard ceiling on the number of tracked IP records.
     *
     * The attempt data lives in a single option row. Under a distributed
     * brute-force attack (many source IPs) this could otherwise grow without
     * bound and bloat the row that is read and written on every failed login.
     * Active lockouts are always kept; the oldest non-locked records are
     * dropped first once the cap is reached.
     */
    const MAX_TRACKED_IPS = 2000;

    /**
     * Register WordPress hooks for this module.
     */
    public function register_hooks() {
        // Priority 99 so we run after WordPress' own authentication callbacks
        // and the lockout decision always wins, even for correct credentials.
        add_filter('authenticate', array($this, 'check_login_lockout'), 99, 3);
        add_action('wp_login_failed', array($this, 'record_failed_login'), 10, 1);
        add_action('wp_login', array($this, 'clear_attempts_on_success'), 10, 2);
    }

    /**
     * Is login limiting on, either per-site or forced network-wide?
     */
    private function limiting_enabled() {
        if (get_option('mbr_custom_login_limit_enabled', 0)) {
            return true;
        }
        return (bool) MBR_Login_Options::network_get('mbr_custom_login_network_lockout', 0);
    }

    /**
     * Get the visitor's IP address.
     *
     * Defaults to REMOTE_ADDR, which the web server sets and a client cannot
     * forge. If the site is flagged as being behind a proxy/CDN, the real
     * client IP is read from a SINGLE admin-chosen header.
     *
     * Earlier versions walked a list of headers and trusted the first valid
     * value found. Because any of those headers (X-Forwarded-For, X-Real-IP)
     * can be sent by an attacker hitting the origin directly, that allowed the
     * lockout to be evaded (rotate the header) or weaponised (send a victim's
     * IP). Trusting exactly one header that the chosen CDN is known to set
     * closes that gap. The admin is responsible for ensuring the origin only
     * accepts traffic from that proxy.
     */
    public static function get_client_ip() {
        $behind_proxy = get_option('mbr_custom_login_behind_proxy', 0);

        if ($behind_proxy) {
            $header = get_option('mbr_custom_login_proxy_header', 'HTTP_CF_CONNECTING_IP');
            $allowed_headers = array(
                'HTTP_CF_CONNECTING_IP', // Cloudflare
                'HTTP_TRUE_CLIENT_IP',   // Akamai / Cloudflare Enterprise
                'HTTP_X_REAL_IP',        // Common nginx reverse proxy
                'HTTP_X_FORWARDED_FOR',  // Generic proxies (may be a list)
            );
            if (!in_array($header, $allowed_headers, true)) {
                $header = 'HTTP_CF_CONNECTING_IP';
            }

            if (!empty($_SERVER[$header])) {
                $value = wp_unslash($_SERVER[$header]);

                // X-Forwarded-For may be "client, proxy1, proxy2"; the first
                // entry is the originating client as recorded by the proxy.
                if ($header === 'HTTP_X_FORWARDED_FOR') {
                    $parts = explode(',', $value);
                    $value = trim($parts[0]);
                } else {
                    $value = trim($value);
                }

                if (filter_var($value, FILTER_VALIDATE_IP)) {
                    return $value;
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
     * Read the attempt data option (and prune fully-expired entries).
     */
    public function get_attempt_data() {
        $data = get_option(self::ATTEMPT_OPTION, array());
        if (!is_array($data)) {
            $data = array();
        }

        $now = time();
        $changed = false;
        foreach ($data as $key => $rec) {
            $window_done  = empty($rec['window_expires']) || $rec['window_expires'] < $now;
            $lock_done    = empty($rec['lock_until']) || $rec['lock_until'] < $now;
            $offense_done = empty($rec['offense_expires']) || $rec['offense_expires'] < $now;
            // Keep a record while it is still counting, still locked, or still
            // within its offense-memory window (so repeat lockouts escalate).
            if ($window_done && $lock_done && $offense_done) {
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
    public function save_attempt_data($data) {
        update_option(self::ATTEMPT_OPTION, $data, false);
    }

    /**
     * How long (hours) an IP's offence count is remembered for escalation.
     */
    private function offense_memory_hours() {
        return max(1, (int) get_option('mbr_custom_login_offense_memory', 24));
    }

    /**
     * Lockout duration in seconds for a given base and prior offence count.
     *
     * With progressive lockouts on, each prior offence multiplies the base
     * duration (base, base×m, base×m^2, ...), capped at the configured maximum.
     *
     * @param int $base_mins       Base lockout in minutes.
     * @param int $prior_offenses  Number of times this IP has already been locked.
     * @return int Seconds.
     */
    private function lockout_seconds($base_mins, $prior_offenses) {
        $base_secs = $base_mins * MINUTE_IN_SECONDS;

        if (!get_option('mbr_custom_login_progressive_enabled', 1) || $prior_offenses < 1) {
            $secs = $base_secs;
        } else {
            $mult = max(1, (int) get_option('mbr_custom_login_lockout_multiplier', 2));
            $secs = (int) round($base_secs * pow($mult, $prior_offenses));
        }

        $max_mins = max($base_mins, (int) get_option('mbr_custom_login_lockout_max', 1440));
        return min($secs, $max_mins * MINUTE_IN_SECONDS);
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

        if (!$this->limiting_enabled()) {
            return $user;
        }

        $ip = self::get_client_ip();
        if (MBR_Login_Access::is_whitelisted($ip)) {
            return $user;
        }

        $data = $this->get_attempt_data();
        $key  = $this->ip_key($ip);

        if (!empty($data[$key]['lock_until']) && $data[$key]['lock_until'] > time()) {
            $remaining = $data[$key]['lock_until'] - time();
            $minutes   = max(1, (int) ceil($remaining / 60));

            /**
             * Fires when a login attempt is blocked because the IP is locked
             * out. The log module listens for this to record a 'lockout' event.
             *
             * @param string $ip       The (already resolved) client IP.
             * @param string $username The submitted username.
             */
            do_action('mbr_login_customiser_lockout', $ip, $username);

            return new WP_Error(
                'mbr_login_locked',
                sprintf(
                    /* translators: %d: number of minutes remaining */
                    _n(
                        '<strong>Too many failed attempts.</strong> Please try again in %d minute.',
                        '<strong>Too many failed attempts.</strong> Please try again in %d minutes.',
                        $minutes,
                        'mbr-login-customiser'
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
        if (!$this->limiting_enabled()) {
            return;
        }

        $ip = self::get_client_ip();
        if (MBR_Login_Access::is_whitelisted($ip)) {
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

        // Reset the counter if the rolling window has expired, but carry the
        // offence history forward while it is still within the memory window so
        // progressive lockouts keep escalating across separate bursts.
        if (empty($data[$key]) || empty($data[$key]['window_expires']) || $data[$key]['window_expires'] < $now) {
            $keep_offenses = 0;
            $keep_expires  = 0;
            if (!empty($data[$key]['offenses'])
                && !empty($data[$key]['offense_expires'])
                && $data[$key]['offense_expires'] >= $now) {
                $keep_offenses = (int) $data[$key]['offenses'];
                $keep_expires  = (int) $data[$key]['offense_expires'];
            }
            $data[$key] = array(
                'fails'           => 0,
                'window_expires'  => $now + ($window_mins * MINUTE_IN_SECONDS),
                'lock_until'      => 0,
                'offenses'        => $keep_offenses,
                'offense_expires' => $keep_expires,
            );
        }

        $data[$key]['fails']++;
        $data[$key]['ip']   = $ip;
        $data[$key]['last'] = $now;

        if ($data[$key]['fails'] >= $max) {
            $duration = $this->lockout_seconds($lockout_mins, (int) $data[$key]['offenses']);

            $data[$key]['offenses']        = (int) $data[$key]['offenses'] + 1;
            $data[$key]['offense_expires'] = $now + ($this->offense_memory_hours() * HOUR_IN_SECONDS);
            $data[$key]['lock_until']      = $now + $duration;
            $data[$key]['fails']           = 0; // reset so the next window starts fresh

            /**
             * Fires the moment an IP crosses the threshold and is locked, so the
             * lockout is logged even if the attacker then stops trying.
             *
             * @param string $ip       The (already resolved) client IP.
             * @param string $username The submitted username.
             */
            do_action('mbr_login_customiser_lockout', $ip, $username);
        }

        // Keep the store bounded. Never evict an active lockout; drop the
        // least-recently-seen non-locked records until we are under the cap.
        if (count($data) > self::MAX_TRACKED_IPS) {
            $evictable = array();
            foreach ($data as $k => $rec) {
                if (empty($rec['lock_until']) || $rec['lock_until'] <= $now) {
                    $evictable[$k] = isset($rec['last']) ? $rec['last'] : 0;
                }
            }
            asort($evictable); // oldest 'last' first
            foreach (array_keys($evictable) as $k) {
                if (count($data) <= self::MAX_TRACKED_IPS) {
                    break;
                }
                if ($k === $key) {
                    continue; // don't drop the record we just touched
                }
                unset($data[$k]);
            }
        }

        $this->save_attempt_data($data);
    }

    /**
     * Clear an IP's record after a successful login.
     */
    public function clear_attempts_on_success($user_login, $user = null) {
        $ip   = self::get_client_ip();
        $data = $this->get_attempt_data();
        $key  = $this->ip_key($ip);

        if (isset($data[$key])) {
            unset($data[$key]);
            $this->save_attempt_data($data);
        }
    }
}
