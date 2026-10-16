<?php
/**
 * WP ShieldX Repair & Remediation Engine
 * Provides Quarantine, Restoration from WordPress.org, Permanent Deletion, and Baseline Updates.
 */

if (!defined('ABSPATH')) {
    exit;
}

class WP_ShieldX_Repair {

    /**
     * Get quarantine directory path
     */
    public static function get_quarantine_dir() {
        $upload_dir = wp_upload_dir();
        $dir = trailingslashit($upload_dir['basedir']) . 'wp-shieldx-quarantine/';

        if (!file_exists($dir)) {
            wp_mkdir_p($dir);
            // Protect quarantine directory with restrictive .htaccess compatible with Apache 2.2 & 2.4
            $htaccess = "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order Deny,Allow\n    Deny from all\n</IfModule>\n<Files *>\n    <IfModule mod_authz_core.c>\n        Require all denied\n    </IfModule>\n    <IfModule !mod_authz_core.c>\n        Order Deny,Allow\n        Deny from all\n    </IfModule>\n</Files>\n";
            file_put_contents($dir . '.htaccess', $htaccess);
            file_put_contents($dir . 'index.php', "<?php\n// Security quarantine vault\nexit;\n");
        }

        return $dir;
    }

    /**
     * Quarantine a suspicious file
     *
     * @param string $file_path Absolute path to file
     * @return array Result [success => bool, message => string]
     */
    public static function quarantine_file($file_path) {
        global $wpdb;

        if (!file_exists($file_path) || !is_file($file_path)) {
            return ['success' => false, 'message' => __('Target file does not exist.', 'wp-shieldx')];
        }

        $quarantine_dir = self::get_quarantine_dir();
        $file_hash = hash_file('sha256', $file_path);
        $file_size = filesize($file_path);
        $perms     = substr(sprintf('%o', fileperms($file_path)), -4);

        $safe_name = $file_hash . '_' . time() . '.quarantined';
        $dest_path = $quarantine_dir . $safe_name;

        // Move the file
        if (!@rename($file_path, $dest_path)) {
            if (!@copy($file_path, $dest_path)) {
                return ['success' => false, 'message' => __('Failed to move file to quarantine. Check directory permissions.', 'wp-shieldx')];
            }
            @unlink($file_path);
        }

        // Restrict destination file permissions
        @chmod($dest_path, 0400);

        // Record in quarantine table
        $table = WP_ShieldX_Database::get_table_name('quarantine');
        $wpdb->insert($table, [
            'original_path'    => $file_path,
            'quarantined_path' => $dest_path,
            'file_hash'        => $file_hash,
            'file_size'        => $file_size,
            'permissions'      => $perms,
            'quarantined_at'   => current_time('mysql'),
            'status'           => 'quarantined'
        ]);

        $quarantine_id = $wpdb->insert_id;

        // Update scan results table status
        $scan_table = WP_ShieldX_Database::get_table_name('scan_results');
        $wpdb->update($scan_table, ['status' => 'quarantined'], ['file_path' => $file_path]);

        // Update baseline status
        $baseline_table = WP_ShieldX_Database::get_table_name('file_baseline');
        $wpdb->update($baseline_table, ['file_status' => 'quarantined'], ['file_path' => $file_path]);

        return [
            'success'       => true,
            'quarantine_id' => $quarantine_id,
            'message'       => sprintf(__('File successfully quarantined to vault: %s', 'wp-shieldx'), esc_html(basename($file_path)))
        ];
    }

    /**
     * Restore a quarantined file back to original location
     *
     * @param int $quarantine_id
     * @return array Result
     */
    public static function restore_quarantined_file($quarantine_id) {
        global $wpdb;

        $table = WP_ShieldX_Database::get_table_name('quarantine');
        $record = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE id = %d", $quarantine_id));

        if (!$record) {
            return ['success' => false, 'message' => __('Quarantine record not found.', 'wp-shieldx')];
        }

        if (!file_exists($record->quarantined_path)) {
            return ['success' => false, 'message' => __('Quarantined file missing from vault.', 'wp-shieldx')];
        }

        $dest_dir = dirname($record->original_path);
        if (!file_exists($dest_dir)) {
            wp_mkdir_p($dest_dir);
        }

        if (!@copy($record->quarantined_path, $record->original_path)) {
            return ['success' => false, 'message' => __('Unable to restore file to original path.', 'wp-shieldx')];
        }

        @unlink($record->quarantined_path);

        $wpdb->update($table, ['status' => 'restored'], ['id' => $quarantine_id]);

        // Mark as restored in scan results
        $scan_table = WP_ShieldX_Database::get_table_name('scan_results');
        $wpdb->update($scan_table, ['status' => 'repaired'], ['file_path' => $record->original_path]);

        return ['success' => true, 'message' => __('File successfully restored from quarantine.', 'wp-shieldx')];
    }

    /**
     * Repair/Restore a WordPress Core file by downloading pristine original from WordPress.org
     *
     * @param string $relative_path Path relative to ABSPATH (e.g. wp-login.php, wp-includes/pluggable.php)
     * @return array
     */
    public static function repair_core_file($relative_path) {
        global $wp_version;

        $relative_path = ltrim($relative_path, '/\\');
        $target_file   = ABSPATH . $relative_path;

        // Core files only: cannot repair custom plugin/theme files through WordPress.org core SVN
        if (strpos($relative_path, 'wp-content/') === 0) {
            return ['success' => false, 'message' => __('Cannot auto-repair custom wp-content files via core API.', 'wp-shieldx')];
        }

        // Fetch pristine file from WordPress Core GitHub or SVN raw
        $clean_urls = [
            sprintf('https://raw.githubusercontent.com/WordPress/WordPress/%s/%s', $wp_version, $relative_path),
            sprintf('https://core.svn.wordpress.org/tags/%s/%s', $wp_version, $relative_path)
        ];

        $content = false;
        foreach ($clean_urls as $url) {
            $response = wp_remote_get($url, ['timeout' => 20, 'sslverify' => true]);
            if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
                $content = wp_remote_retrieve_body($response);
                break;
            }
        }

        if ($content === false || strlen($content) === 0) {
            return ['success' => false, 'message' => sprintf(__('Failed to download authentic core file for version %s.', 'wp-shieldx'), esc_html($wp_version))];
        }

        // Backup existing infected/modified file to quarantine first
        if (file_exists($target_file)) {
            self::quarantine_file($target_file);
        }

        // Write authentic file
        if (@file_put_contents($target_file, $content) === false) {
            return ['success' => false, 'message' => __('Failed to write pristine file. Check directory permissions.', 'wp-shieldx')];
        }

        // Update baseline with pristine file's hash
        $new_hash = hash('sha256', $content);
        $baseline_table = WP_ShieldX_Database::get_table_name('file_baseline');
        global $wpdb;
        $wpdb->replace($baseline_table, [
            'file_path'     => $target_file,
            'relative_path' => $relative_path,
            'file_hash'     => $new_hash,
            'file_size'     => strlen($content),
            'file_mtime'    => time(),
            'file_status'   => 'clean',
            'last_scanned'  => current_time('mysql')
        ]);

        // Resolve threat in scan results
        $scan_table = WP_ShieldX_Database::get_table_name('scan_results');
        $wpdb->update($scan_table, ['status' => 'repaired'], ['relative_path' => $relative_path]);

        return ['success' => true, 'message' => sprintf(__('Successfully repaired %s using official WordPress %s core files!', 'wp-shieldx'), esc_html($relative_path), esc_html($wp_version))];
    }

    /**
     * Permanently delete a malicious file
     *
     * @param string $file_path
     * @return array
     */
    public static function delete_file($file_path) {
        global $wpdb;

        if (!file_exists($file_path)) {
            return ['success' => false, 'message' => __('Target file does not exist.', 'wp-shieldx')];
        }

        if (@unlink($file_path)) {
            $scan_table = WP_ShieldX_Database::get_table_name('scan_results');
            $wpdb->update($scan_table, ['status' => 'deleted'], ['file_path' => $file_path]);

            $baseline_table = WP_ShieldX_Database::get_table_name('file_baseline');
            $wpdb->delete($baseline_table, ['file_path' => $file_path]);

            return ['success' => true, 'message' => __('Malicious file permanently deleted.', 'wp-shieldx')];
        }

        return ['success' => false, 'message' => __('Failed to delete file. Check file system permissions.', 'wp-shieldx')];
    }

    /**
     * Whitelist / Accept a modified file into baseline
     *
     * @param string $file_path
     * @return array
     */
    public static function whitelist_file($file_path) {
        global $wpdb;

        if (!file_exists($file_path)) {
            return ['success' => false, 'message' => __('File does not exist.', 'wp-shieldx')];
        }

        $relative = ltrim(str_replace(wp_normalize_path(ABSPATH), '', wp_normalize_path($file_path)), '/\\');
        $hash     = hash_file('sha256', $file_path);
        $size     = filesize($file_path);
        $mtime    = filemtime($file_path);

        $baseline_table = WP_ShieldX_Database::get_table_name('file_baseline');
        $wpdb->replace($baseline_table, [
            'file_path'     => $file_path,
            'relative_path' => $relative,
            'file_hash'     => $hash,
            'file_size'     => $size,
            'file_mtime'    => $mtime,
            'file_status'   => 'clean',
            'last_scanned'  => current_time('mysql')
        ]);

        $scan_table = WP_ShieldX_Database::get_table_name('scan_results');
        $wpdb->update($scan_table, ['status' => 'ignored'], ['file_path' => $file_path]);

        return ['success' => true, 'message' => __('File changes accepted and updated in baseline.', 'wp-shieldx')];
    }

    /**
     * Protect Uploads folder by preventing script execution via .htaccess
     */
    public static function lockdown_uploads_folder() {
        $upload_dir = wp_upload_dir();
        $target_htaccess = trailingslashit($upload_dir['basedir']) . '.htaccess';

        $rules = "# WP ShieldX Security Uploads Lockdown\n" .
                 "<FilesMatch \"\.(?i:php|phtml|php3|php4|php5|php7|php8|phar|inc|pl|py|cgi|sh)\$\">\n" .
                 "    <IfModule mod_authz_core.c>\n" .
                 "        Require all denied\n" .
                 "    </IfModule>\n" .
                 "    <IfModule !mod_authz_core.c>\n" .
                 "        Order Deny,Allow\n" .
                 "        Deny from all\n" .
                 "    </IfModule>\n" .
                 "</FilesMatch>\n";

        if (file_put_contents($target_htaccess, $rules)) {
            return ['success' => true, 'message' => __('Uploads folder execution locked down successfully.', 'wp-shieldx')];
        }

        return ['success' => false, 'message' => __('Failed to write .htaccess in uploads directory.', 'wp-shieldx')];
    }
}
