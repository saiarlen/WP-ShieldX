<?php
/**
 * WP ShieldX File Integrity Monitor (FIM)
 * Continuously tracks file creation, modification, and deletion across WordPress.
 */

if (!defined('ABSPATH')) {
    exit;
}

class WP_ShieldX_File_Monitor {

    /**
     * File extensions to monitor actively
     */
    protected static $monitored_extensions = [
        'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phar',
        'js', 'html', 'htm', 'htaccess', 'svg', 'sql', 'sh', 'py'
    ];

    /**
     * Get directories to exclude from monitor to prevent performance issues & false self-alerts
     */
    public static function get_excluded_dirs() {
        $excluded = [
            'wp-content/cache',
            'wp-content/uploads/wp-shieldx-quarantine',
            'node_modules',
            '.git',
            '.svn'
        ];

        // Automatically exclude WP ShieldX's own plugin folder so plugin self-updates don't trigger false alarms
        if (defined('WP_SHIELDX_PATH') && defined('ABSPATH')) {
            $root = wp_normalize_path(ABSPATH);
            $self_dir = wp_normalize_path(WP_SHIELDX_PATH);
            $rel = trim(str_replace($root, '', $self_dir), '/\\');
            if (!empty($rel)) {
                $excluded[] = $rel;
            }
        }

        return $excluded;
    }

    /**
     * Initialize Real-Time Monitoring Hooks
     */
    public static function init_realtime_hooks() {
        // 1. Real-time file upload inspection (intercepts rogue uploads in memory before saving)
        add_filter('wp_handle_upload_prefilter', [__CLASS__, 'inspect_uploaded_file']);

        // 2. Real-time post-upload registration into baseline
        add_filter('wp_handle_upload', [__CLASS__, 'on_file_uploaded']);

        // 3. Real-time core/plugin/theme upgrade sync (prevents false positive modified alerts)
        add_action('upgrader_process_complete', [__CLASS__, 'on_upgrade_complete'], 10, 2);

        // 4. Real-time critical root files micro-check on admin load
        add_action('admin_init', [__CLASS__, 'check_critical_files']);
    }

    /**
     * Real-time upload inspection: blocks executable scripts and polyglot webshells immediately
     */
    public static function inspect_uploaded_file($file) {
        if (empty($file['name'])) {
            return $file;
        }

        $filename = strtolower($file['name']);
        $ext = pathinfo($filename, PATHINFO_EXTENSION);

        // Block any executable script upload immediately
        if (WP_ShieldX_Signatures::is_executable_extension($filename) || in_array($ext, ['exe', 'bat', 'cmd', 'sh', 'py', 'pl', 'cgi'], true)) {
            $ip = WP_ShieldX_Firewall::get_client_ip();
            WP_ShieldX_Notifier::notify(
                'FIREWALL_ATTACK',
                sprintf(__('Real-Time Threat Blocked: Executable Upload Attempt (%s)', 'wp-shieldx'), esc_html($file['name'])),
                [
                    'Attacker IP'     => $ip,
                    'Blocked File'    => sanitize_file_name($file['name']),
                    'Action'          => 'Upload terminated in real-time before disk write'
                ],
                'critical'
            );
            $file['error'] = __('Security Error: Uploading executable scripts or programs is strictly prohibited by WP ShieldX.', 'wp-shieldx');
            return $file;
        }

        // Deep content inspection of uploaded file (detects PHP code disguised inside images or media)
        if (!empty($file['tmp_name']) && file_exists($file['tmp_name'])) {
            $buffer = @file_get_contents($file['tmp_name'], false, null, 0, 4096);
            if ($buffer && preg_match('/<\?(?:php|=)/i', $buffer)) {
                $file['error'] = __('Security Error: Embedded PHP payload detected inside uploaded file.', 'wp-shieldx');
                return $file;
            }
        }

        return $file;
    }

    /**
     * When a legitimate file upload completes, index it immediately into baseline
     */
    public static function on_file_uploaded($upload) {
        if (!empty($upload['file']) && file_exists($upload['file'])) {
            global $wpdb;
            $abs_path = wp_normalize_path($upload['file']);
            $root     = wp_normalize_path(ABSPATH);
            $rel_path = ltrim(str_replace($root, '', $abs_path), '/\\');
            $hash     = hash_file('sha256', $abs_path);

            $baseline_table = WP_ShieldX_Database::get_table_name('file_baseline');
            $wpdb->replace($baseline_table, [
                'file_path'     => $abs_path,
                'relative_path' => $rel_path,
                'file_hash'     => $hash,
                'file_size'     => filesize($abs_path),
                'file_mtime'    => filemtime($abs_path),
                'file_status'   => 'clean',
                'last_scanned'  => current_time('mysql')
            ]);
        }
        return $upload;
    }

    /**
     * When plugins/themes/core are updated legitimately via WordPress Upgrader,
     * automatically re-sync the baseline as clean so official updates don't trigger false alarms.
     */
    public static function on_upgrade_complete($upgrader_object, $options) {
        self::build_baseline();
    }

    /**
     * High-speed real-time micro-check for root critical files (wp-config.php, index.php, .htaccess)
     */
    public static function check_critical_files() {
        // Run at most once every 60 seconds per admin session to ensure ultra-low overhead
        $cache_key = 'wp_sec_crit_check_' . get_current_user_id();
        if (get_transient($cache_key)) {
            return;
        }
        set_transient($cache_key, 1, 60);

        $root = wp_normalize_path(ABSPATH);
        $critical_files = [
            $root . 'index.php',
            $root . '.htaccess',
            $root . 'wp-config.php',
            wp_normalize_path(dirname(ABSPATH) . '/wp-config.php')
        ];

        global $wpdb;
        $baseline_table = WP_ShieldX_Database::get_table_name('file_baseline');

        foreach ($critical_files as $file) {
            if (!file_exists($file)) {
                continue;
            }
            $hash = hash_file('sha256', $file);
            $rel = ltrim(str_replace($root, '', $file), '/\\');

            $stored = $wpdb->get_row($wpdb->prepare("SELECT id, file_hash FROM $baseline_table WHERE file_path = %s", $file));
            if ($stored && $stored->file_hash !== $hash) {
                // Critical file modified!
                add_action('admin_notices', function() use ($rel) {
                    echo '<div class="notice notice-error is-dismissible"><p><strong>[WP ShieldX Alert]</strong> Critical root file modified unexpectedly: <code>' . esc_html($rel) . '</code>. Check the <a href="' . esc_url(admin_url('admin.php?page=wp-shieldx-files')) . '">File Monitor</a> immediately!</p></div>';
                });
            }
        }
    }

    /**
     * Run full file integrity check comparing current disk against stored baseline
     *
     * @return array [
     *   'added'    => count,
     *   'modified' => count,
     *   'deleted'  => count,
     *   'total'    => count
     * ]
     */
    public static function check_integrity() {
        global $wpdb;

        $baseline_table = WP_ShieldX_Database::get_table_name('file_baseline');

        // Fetch all currently indexed files in baseline
        $existing_baseline = $wpdb->get_results(
            "SELECT id, file_path, relative_path, file_hash, file_size, file_mtime, file_status FROM $baseline_table",
            OBJECT_K // key by id
        );

        // Map baseline by relative_path
        $baseline_map = [];
        foreach ($existing_baseline as $row) {
            $baseline_map[$row->relative_path] = $row;
        }

        $current_files = self::scan_filesystem();

        $added_files    = [];
        $modified_files = [];
        $deleted_files  = [];
        $clean_files    = 0;

        $scanned_time = current_time('mysql');

        // 1. Check current disk files against baseline
        foreach ($current_files as $relative_path => $file_info) {
            $abs_path = $file_info['path'];

            if (!isset($baseline_map[$relative_path])) {
                // NEW FILE ADDED
                $hash = hash_file('sha256', $abs_path);
                $wpdb->insert($baseline_table, [
                    'file_path'     => $abs_path,
                    'relative_path' => $relative_path,
                    'file_hash'     => $hash,
                    'file_size'     => $file_info['size'],
                    'file_mtime'    => $file_info['mtime'],
                    'file_status'   => 'added',
                    'last_scanned'  => $scanned_time
                ]);
                $added_files[] = $relative_path;
            } else {
                $base = $baseline_map[$relative_path];
                // Quick check: if mtime or size changed, verify hash
                if ($base->file_size != $file_info['size'] || $base->file_mtime != $file_info['mtime']) {
                    $new_hash = hash_file('sha256', $abs_path);
                    if ($new_hash !== $base->file_hash) {
                        // MODIFIED FILE
                        $wpdb->update($baseline_table, [
                            'file_hash'    => $new_hash,
                            'file_size'    => $file_info['size'],
                            'file_mtime'   => $file_info['mtime'],
                            'file_status'  => 'modified',
                            'last_scanned' => $scanned_time
                        ], ['id' => $base->id]);
                        $modified_files[] = $relative_path;
                    } else {
                        // Only timestamp changed, file content identical
                        $wpdb->update($baseline_table, [
                            'file_mtime'   => $file_info['mtime'],
                            'last_scanned' => $scanned_time
                        ], ['id' => $base->id]);
                        $clean_files++;
                    }
                } else {
                    $clean_files++;
                }
                unset($baseline_map[$relative_path]);
            }
        }

        // 2. Any leftover files in baseline_map that are not on disk are DELETED
        foreach ($baseline_map as $relative_path => $base) {
            if ($base->file_status !== 'deleted') {
                $wpdb->update($baseline_table, [
                    'file_status'  => 'deleted',
                    'last_scanned' => $scanned_time
                ], ['id' => $base->id]);
                $deleted_files[] = $relative_path;
            }
        }

        // Send Email Alert if changes were discovered
        $total_changes = count($added_files) + count($modified_files) + count($deleted_files);
        if ($total_changes > 0) {
            $details = [
                'New Files Added' => count($added_files),
                'Files Modified'  => count($modified_files),
                'Files Deleted'   => count($deleted_files),
                'Sample Changes'  => implode(', ', array_slice(array_merge($added_files, $modified_files, $deleted_files), 0, 8))
            ];
            WP_ShieldX_Notifier::notify(
                'FILE_MODIFIED',
                sprintf(__('Integrity Alert: %d file changes detected on your site', 'wp-shieldx'), $total_changes),
                $details,
                'high'
            );
        }

        return [
            'added'    => count($added_files),
            'modified' => count($modified_files),
            'deleted'  => count($deleted_files),
            'clean'    => $clean_files,
            'total'    => count($current_files)
        ];
    }

    /**
     * Build initial baseline database (run on activation or baseline rebuild)
     */
    public static function build_baseline() {
        @set_time_limit(300);
        if (function_exists('wp_raise_memory_limit')) {
            wp_raise_memory_limit('admin');
        }

        global $wpdb;

        $baseline_table = WP_ShieldX_Database::get_table_name('file_baseline');
        $wpdb->query("TRUNCATE TABLE $baseline_table");

        $files = self::scan_filesystem();
        $scanned_time = current_time('mysql');

        $batch = [];
        $count = 0;

        foreach ($files as $relative_path => $file_info) {
            $hash = @hash_file('sha256', $file_info['path']);
            if (!$hash) {
                continue;
            }

            $batch[] = $wpdb->prepare(
                "(%s, %s, %s, %d, %d, 'clean', %s)",
                $file_info['path'],
                $relative_path,
                $hash,
                $file_info['size'],
                $file_info['mtime'],
                $scanned_time
            );

            if (count($batch) >= 100) {
                $query = "INSERT INTO $baseline_table (file_path, relative_path, file_hash, file_size, file_mtime, file_status, last_scanned) VALUES " . implode(',', $batch);
                $wpdb->query($query);
                $batch = [];
            }
            $count++;
        }

        if (!empty($batch)) {
            $query = "INSERT INTO $baseline_table (file_path, relative_path, file_hash, file_size, file_mtime, file_status, last_scanned) VALUES " . implode(',', $batch);
            $wpdb->query($query);
        }

        return $count;
    }

    /**
     * Recursively scan WordPress directories for monitored files
     *
     * @return array [ relative_path => ['path' => abs_path, 'size' => int, 'mtime' => int] ]
     */
    public static function scan_filesystem() {
        $root = wp_normalize_path(ABSPATH);
        $files = [];

        // Traverse WordPress root recursively (includes all root files and subdirectories)
        if (is_dir($root)) {
            self::traverse_directory($root, $root, $files);
        }

        // Also check if wp-config.php is stored in the parent directory (standard WordPress security practice)
        $parent_config = wp_normalize_path(dirname(ABSPATH) . '/wp-config.php');
        if (file_exists($parent_config) && !isset($files['../wp-config.php'])) {
            $files['../wp-config.php'] = [
                'path'  => $parent_config,
                'size'  => filesize($parent_config),
                'mtime' => filemtime($parent_config)
            ];
        }

        return $files;
    }

    /**
     * Directory traversal helper
     */
    protected static function traverse_directory($dir, $root, &$results) {
        $handle = @opendir($dir);
        if (!$handle) {
            return;
        }

        while (($item = readdir($handle)) !== false) {
            if ($item === '.' || $item === '..') {
                continue;
            }

            $full_path = wp_normalize_path($dir . '/' . $item);
            $rel_path  = ltrim(str_replace($root, '', $full_path), '/\\');

            // Exclude directories (including WP ShieldX's own directory)
            $is_excluded = false;
            foreach (self::get_excluded_dirs() as $exc) {
                if (strpos($rel_path, $exc) === 0) {
                    $is_excluded = true;
                    break;
                }
            }
            if ($is_excluded) {
                continue;
            }

            if (is_dir($full_path)) {
                // Avoid recursion into uploads subfolders beyond monitored extensions if too deep
                self::traverse_directory($full_path, $root, $results);
            } elseif (is_file($full_path)) {
                $ext = strtolower(pathinfo($full_path, PATHINFO_EXTENSION));
                $filename = basename($full_path);

                // Check extension or special files like .htaccess, wp-config.php
                if (in_array($ext, self::$monitored_extensions, true) || $filename === '.htaccess' || $filename === 'wp-config.php') {
                    $results[$rel_path] = [
                        'path'  => $full_path,
                        'size'  => filesize($full_path),
                        'mtime' => filemtime($full_path)
                    ];
                }
            }
        }
        closedir($handle);
    }

    /**
     * Get statistics of monitored files
     */
    public static function get_stats() {
        global $wpdb;
        $baseline_table = WP_ShieldX_Database::get_table_name('file_baseline');

        $total    = (int)$wpdb->get_var("SELECT COUNT(*) FROM $baseline_table");
        $added    = (int)$wpdb->get_var("SELECT COUNT(*) FROM $baseline_table WHERE file_status = 'added'");
        $modified = (int)$wpdb->get_var("SELECT COUNT(*) FROM $baseline_table WHERE file_status = 'modified'");
        $deleted  = (int)$wpdb->get_var("SELECT COUNT(*) FROM $baseline_table WHERE file_status = 'deleted'");
        $clean    = (int)$wpdb->get_var("SELECT COUNT(*) FROM $baseline_table WHERE file_status = 'clean'");

        return [
            'total'    => $total,
            'added'    => $added,
            'modified' => $modified,
            'deleted'  => $deleted,
            'clean'    => $clean
        ];
    }

    /**
     * Get list of changed files with pagination & filter
     */
    public static function get_changed_files($filter = 'all', $limit = 50, $offset = 0) {
        global $wpdb;
        $baseline_table = WP_ShieldX_Database::get_table_name('file_baseline');

        $where = "WHERE file_status IN ('added', 'modified', 'deleted')";
        if (in_array($filter, ['added', 'modified', 'deleted', 'clean'], true)) {
            $where = $wpdb->prepare("WHERE file_status = %s", $filter);
        }

        $query = "SELECT * FROM $baseline_table $where ORDER BY last_scanned DESC LIMIT %d OFFSET %d";
        return $wpdb->get_results($wpdb->prepare($query, $limit, $offset));
    }
}
