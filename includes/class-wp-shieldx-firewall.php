<?php
/**
 * WP ShieldX FireShield - Web Application Firewall (WAF)
 * Real-time active request inspection, exploit blocking, brute-force defense, and sensitive endpoint protection.
 */

if (!defined('ABSPATH')) {
    exit;
}

class WP_ShieldX_Firewall {

    /**
     * Initialize firewall hook
     */
    public static function init() {
        // Run firewall as early as possible
        self::inspect_request();

        // Hardening hooks
        add_action('init', [__CLASS__, 'block_user_enumeration']);
        add_filter('xmlrpc_enabled', [__CLASS__, 'filter_xmlrpc']);
        add_action('wp_login_failed', [__CLASS__, 'track_failed_login']);
        add_filter('authenticate', [__CLASS__, 'check_login_rate_limit'], 1, 3);
    }

    /**
     * Inspect incoming HTTP request against attack signatures
     */
    public static function inspect_request() {
        // Skip for CLI or cron
        if (defined('DOING_CRON') && DOING_CRON) {
            return;
        }
        if (defined('WP_CLI') && WP_CLI) {
            return;
        }

        $options = get_option('wp_shieldx_settings', []);
        $waf_enabled = isset($options['waf_enabled']) ? (bool)$options['waf_enabled'] : true;
        if (!$waf_enabled) {
            return;
        }

        $ip = self::get_client_ip();

        // 1. Check IP Whitelist
        if (self::is_ip_whitelisted($ip)) {
            return;
        }

        // 2. Check IP Blacklist
        if (self::is_ip_blacklisted($ip)) {
            self::block_request('IP_BLACKLISTED', 'IP is in permanent blacklist', 'Blocked by administrator');
        }

        // 3. User-Agent Inspection
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        if (preg_match('/(?:sqlmap|nikto|wpscan|havij|acunetix|dirbuster|masscan|gobuster|python-requests\/|nmap|zgrab)/i', $ua)) {
            self::block_request('BAD_BOT_SCANNER', $ua, 'Known Vulnerability Scanner / Malicious User-Agent');
        }

        // 4. Request URI and Query String inspection
        $uri = isset($_SERVER['REQUEST_URI']) ? rawurldecode($_SERVER['REQUEST_URI']) : '';

        // Block direct access to sensitive hidden files
        if (preg_match('/(?:\.git|\.env|wp-config\.php\.bak|\.sql|\.htpasswd|\/debug\.log|\/xmlrpc\.php)/i', $uri)) {
            if (empty($options['disable_xmlrpc_block']) || strpos($uri, 'xmlrpc.php') === false) {
                self::block_request('SENSITIVE_FILE_ACCESS', $uri, 'Attempt to access protected file or endpoint');
            }
        }

        // 5. Deep payload inspection (GET, POST, COOKIE, URI)
        $inputs = [
            'URI'    => $uri,
            'GET'    => $_GET,
            'POST'   => $_POST,
            'COOKIE' => $_COOKIE
        ];

        self::check_attack_patterns($inputs);
    }

    /**
     * Recursively test input arrays for malicious payloads
     */
    protected static function check_attack_patterns($data, $prefix = '') {
        foreach ($data as $key => $val) {
            $context = $prefix ? "{$prefix}[{$key}]" : $key;

            if (is_array($val)) {
                self::check_attack_patterns($val, $context);
                continue;
            }

            $str = (string)$val;
            if (empty($str)) {
                continue;
            }

            // Path Traversal & LFI
            if (preg_match('/(?:\.\.\/|\.\.\\\\|\%2e\%2e|\/etc\/passwd|c:\\\\boot\.ini)/i', $str)) {
                self::block_request('PATH_TRAVERSAL_LFI', "{$context}: {$str}", 'Directory traversal / LFI attack attempt');
            }

            // PHP Stream Wrappers & RFI
            if (preg_match('/(?:php:\/\/input|php:\/\/filter|data:\/\/text\/plain|expect:\/\/)/i', $str)) {
                self::block_request('PHP_WRAPPER_EXPLOIT', "{$context}: {$str}", 'Malicious PHP wrapper execution attempt');
            }

            // SQL Injection
            if (preg_match('/(?:\bunion\s+(?:all\s+)?select\b|\bselect\b.*?\bfrom\b.*?\binformation_schema\b|benchmark\s*\(\s*\d+\s*,|sleep\s*\(\s*\d+\s*\)|waitfor\s+delay\s+[\'"]|\b(?:exec|execute)\s*\(|\'\s*or\s*1\s*=\s*1|\'\s*or\s*\'[a-z0-9]\'\s*=\s*\'[a-z0-9])/i', $str)) {
                self::block_request('SQL_INJECTION', "{$context}: {$str}", 'SQL Injection pattern detected');
            }

            // Cross-Site Scripting (XSS)
            if (preg_match('/(?:<script\b[^>]*>.*?<\/script>|<script\b|<[^>]+\bon(?:error|load|click|mouseover|mouseenter)\s*=|(?:javascript|vbscript):|document\.cookie)/i', $str)) {
                self::block_request('XSS_ATTACK', "{$context}: {$str}", 'Cross-Site Scripting (XSS) pattern detected');
            }
        }
    }

    /**
     * Block request, record event, notify admin, and output security block page
     */
    public static function block_request($attack_type, $payload, $reason) {
        global $wpdb;

        $ip = self::get_client_ip();
        $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        $method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';

        // Truncate payload for database storage
        $truncated_payload = substr($payload, 0, 1000);

        // Record in database
        $table = WP_ShieldX_Database::get_table_name('firewall_logs');
        $wpdb->insert($table, [
            'ip_address'     => $ip,
            'request_uri'    => substr($uri, 0, 500),
            'request_method' => $method,
            'user_agent'     => substr($ua, 0, 500),
            'attack_type'    => $attack_type,
            'payload'        => $truncated_payload,
            'action_taken'   => 'blocked',
            'created_at'     => current_time('mysql')
        ]);

        $log_id = $wpdb->insert_id;

        // Dispatch email notification
        WP_ShieldX_Notifier::notify(
            'FIREWALL_ATTACK',
            sprintf(__('Firewall Blocked %s Attack from IP %s', 'wp-shieldx'), $attack_type, $ip),
            [
                'Attacking IP' => $ip,
                'Attack Type'  => $attack_type,
                'Reason'       => $reason,
                'Request URI'  => $uri,
                'User Agent'   => $ua
            ],
            'high'
        );

        // Render Security 403 Page
        status_header(403);
        nocache_headers();

        $incident_id = 'WPS-' . strtoupper(substr(md5($log_id . $ip . time()), 0, 10));

        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>403 Forbidden - WP ShieldX Protection</title>
            <style>
                * { box-sizing: border-box; }
                body { margin: 0; padding: 0; background-color: #0b1120; color: #94a3b8; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
                .shield-card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; max-width: 540px; width: 90%; padding: 40px; text-align: center; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); }
                .icon { font-size: 54px; margin-bottom: 16px; color: #f43f5e; }
                h1 { margin: 0 0 10px; font-size: 24px; color: #f8fafc; font-weight: 700; }
                p { font-size: 14px; line-height: 1.6; margin: 0 0 20px; color: #cbd5e1; }
                .details { background: #0f172a; border-radius: 8px; padding: 16px; text-align: left; font-family: monospace; font-size: 12px; margin-bottom: 24px; border: 1px solid #1e293b; color: #38bdf8; word-break: break-all; }
                .details div { margin-bottom: 6px; }
                .details span { color: #64748b; }
                .footer { font-size: 12px; color: #64748b; }
            </style>
        </head>
        <body>
            <div class="shield-card">
                <div class="icon">&#128737;&#65039;</div>
                <h1>Access Blocked by WP ShieldX</h1>
                <p>Your request was flagged by our real-time firewall as potentially malicious. This action has been logged and reported to site administrators.</p>
                <div class="details">
                    <div><span>Incident ID:</span> <?php echo esc_html($incident_id); ?></div>
                    <div><span>Client IP:</span> <?php echo esc_html($ip); ?></div>
                    <div><span>Threat Classification:</span> <?php echo esc_html($attack_type); ?></div>
                    <div><span>Timestamp:</span> <?php echo esc_html(gmdate('Y-m-d H:i:s')); ?> UTC</div>
                </div>
                <div class="footer">
                    WP ShieldX Advanced Security Engine &bull; Protected by Firewall
                </div>
            </div>
        </body>
        </html>
        <?php
        exit;
    }

    /**
     * Block Author Enumeration (?author=N and /wp-json/wp/v2/users)
     */
    public static function block_user_enumeration() {
        if (is_admin()) {
            return;
        }

        // Block ?author=1 query
        if (isset($_REQUEST['author']) && is_numeric($_REQUEST['author'])) {
            self::block_request('USER_ENUMERATION', 'author=' . sanitize_text_field($_REQUEST['author']), 'Username scanning via author parameter');
        }

        // Block REST API user list for unauthenticated requests
        add_filter('rest_endpoints', function($endpoints) {
            if (!is_user_logged_in() && isset($endpoints['/wp/v2/users'])) {
                unset($endpoints['/wp/v2/users']);
            }
            return $endpoints;
        });
    }

    /**
     * Disable XML-RPC if option enabled
     */
    public static function filter_xmlrpc($enabled) {
        $options = get_option('wp_shieldx_settings', []);
        if (!empty($options['disable_xmlrpc'])) {
            return false;
        }
        return $enabled;
    }

    /**
     * Track failed login attempts for brute force mitigation
     */
    public static function track_failed_login($username) {
        $ip = self::get_client_ip();
        $transient_key = 'wp_sec_bf_' . md5($ip);
        $attempts = (int)get_transient($transient_key);
        $attempts++;

        set_transient($transient_key, $attempts, 15 * MINUTE_IN_SECONDS);

        if ($attempts >= 5) {
            self::add_to_blacklist($ip, 'Automatic brute-force ban after multiple failed login attempts');
            WP_ShieldX_Notifier::notify(
                'FIREWALL_ATTACK',
                sprintf(__('Brute Force Attack Detected: IP %s Banned', 'wp-shieldx'), $ip),
                [
                    'Banned IP' => $ip,
                    'Username Attempted' => sanitize_text_field($username),
                    'Attempts'  => $attempts,
                    'Duration'  => '24 Hours'
                ],
                'critical'
            );
        }
    }

    /**
     * Check if client IP is currently rate-limited on login
     */
    public static function check_login_rate_limit($user, $username, $password) {
        $ip = self::get_client_ip();
        $transient_key = 'wp_sec_bf_' . md5($ip);
        $attempts = (int)get_transient($transient_key);

        if ($attempts >= 5) {
            return new WP_Error(
                'too_many_attempts',
                __('<strong>ERROR</strong>: Too many failed login attempts. Your IP has been temporarily locked out by WP ShieldX.', 'wp-shieldx')
            );
        }

        return $user;
    }

    /**
     * Client IP resolution helper
     */
    public static function get_client_ip() {
        $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
        foreach ($headers as $h) {
            if (!empty($_SERVER[$h])) {
                $ips = explode(',', $_SERVER[$h]);
                $ip = trim($ips[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        return '127.0.0.1';
    }

    public static function is_ip_whitelisted($ip) {
        $options = get_option('wp_shieldx_settings', []);
        $whitelist = !empty($options['ip_whitelist']) ? explode("\n", $options['ip_whitelist']) : [];
        $whitelist = array_map('trim', $whitelist);
        return in_array($ip, $whitelist, true);
    }

    public static function is_ip_blacklisted($ip) {
        $options = get_option('wp_shieldx_settings', []);
        $blacklist = !empty($options['ip_blacklist']) ? explode("\n", $options['ip_blacklist']) : [];
        $blacklist = array_map('trim', $blacklist);
        return in_array($ip, $blacklist, true);
    }

    public static function add_to_blacklist($ip, $reason = '') {
        $options = get_option('wp_shieldx_settings', []);
        $current = !empty($options['ip_blacklist']) ? $options['ip_blacklist'] : '';
        $list = array_filter(array_map('trim', explode("\n", $current)));
        if (!in_array($ip, $list, true)) {
            $list[] = $ip;
            $options['ip_blacklist'] = implode("\n", $list);
            update_option('wp_shieldx_settings', $options);
        }
    }
}
