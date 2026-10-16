<?php
/**
 * WP ShieldX Auto-Backup & 1-Click Rollback Vault
 * Creates automatic snapshots before plugin/theme updates and provides instant one-click rollback.
 */

if (!defined('ABSPATH')) {
    exit;
}

class WP_ShieldX_Backup {

    /**
     * Initialize automatic update hooks
     */
    public static function init() {
        // Intercept updates before replacement
        add_filter('upgrader_pre_install', [__CLASS__, 'on_pre_install'], 10, 2);
    }

    /**
     * Get backup storage directory
     */
    public static function get_backup_dir() {
        $quarantine_dir = WP_ShieldX_Repair::get_quarantine_dir();
        $backup_dir = trailingslashit($quarantine_dir) . 'backups/';
        if (!file_exists($backup_dir)) {
            wp_mkdir_p($backup_dir);
            @file_put_contents($backup_dir . 'index.php', "<?php exit;");
        }
        return $backup_dir;
    }

    /**
     * Automatically capture a snapshot before an upgrader replaces files
     */
    public static function on_pre_install($return, $hook_extra) {
        if (is_wp_error($return)) {
            return $return;
        }

        // Determine if plugin or theme is being updated
        if (isset($hook_extra['plugin'])) {
            $plugin_file = $hook_extra['plugin'];
            $slug = dirname($plugin_file);
            if ($slug !== '.' && !empty($slug)) {
                $dir = wp_normalize_path(WP_PLUGIN_DIR . '/' . $slug);
                self::create_snapshot($slug, 'plugin', $dir);
            }
        } elseif (isset($hook_extra['theme'])) {
            $theme_slug = $hook_extra['theme'];
            $theme_dir  = wp_normalize_path(get_theme_root() . '/' . $theme_slug);
            self::create_snapshot($theme_slug, 'theme', $theme_dir);
        }

        return $return;
    }

    /**
     * Create a compressed zip snapshot of a directory
     *
     * @param string $slug
     * @param string $type 'plugin' or 'theme'
     * @param string $source_dir
     * @return array Result
     */
    public static function create_snapshot($slug, $type, $source_dir) {
        if (!is_dir($source_dir) || !class_exists('ZipArchive')) {
            return ['success' => false, 'message' => __('ZipArchive extension not available or source missing.', 'wp-shieldx')];
        }

        $backup_dir = self::get_backup_dir();
        $filename   = sanitize_key($slug) . '_' . date('Ymd_His') . '.zip';
        $dest_zip   = $backup_dir . $filename;

        $zip = new ZipArchive();
        if ($zip->open($dest_zip, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            return ['success' => false, 'message' => __('Unable to create zip archive.', 'wp-shieldx')];
        }

        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($source_dir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($files as $file) {
            if (!$file->isDir()) {
                $filePath = $file->getRealPath();
                $relativePath = substr($filePath, strlen($source_dir) + 1);
                $zip->addFile($filePath, $relativePath);
            }
        }

        $zip->close();
        $size = filesize($dest_zip);

        // Record snapshot in database
        global $wpdb;
        $table = WP_ShieldX_Database::get_table_name('backups');
        $wpdb->insert($table, [
            'item_type'   => $type,
            'item_slug'   => $slug,
            'backup_path' => $dest_zip,
            'file_size'   => $size,
            'created_at'  => current_time('mysql'),
            'status'      => 'ready'
        ]);

        return [
            'success'   => true,
            'backup_id' => $wpdb->insert_id,
            'filename'  => $filename,
            'message'   => sprintf(__('Auto-backup snapshot created for %s before update.', 'wp-shieldx'), esc_html($slug))
        ];
    }

    /**
     * 1-Click Rollback: restores files from a snapshot back to active directory
     *
     * @param int $backup_id
     * @return array
     */
    public static function rollback_snapshot($backup_id) {
        global $wpdb;
        $table = WP_ShieldX_Database::get_table_name('backups');
        $record = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE id = %d", $backup_id));

        if (!$record || !file_exists($record->backup_path)) {
            return ['success' => false, 'message' => __('Snapshot file not found in vault.', 'wp-shieldx')];
        }

        $target_dir = ($record->item_type === 'theme') ? (get_theme_root() . '/' . $record->item_slug) : (WP_PLUGIN_DIR . '/' . $record->item_slug);
        $target_dir = wp_normalize_path($target_dir);

        if (!class_exists('ZipArchive')) {
            return ['success' => false, 'message' => __('ZipArchive extension not available on this server.', 'wp-shieldx')];
        }

        $zip = new ZipArchive();
        if ($zip->open($record->backup_path) !== true) {
            return ['success' => false, 'message' => __('Failed to open snapshot zip.', 'wp-shieldx')];
        }

        if (!file_exists($target_dir)) {
            wp_mkdir_p($target_dir);
        }

        $zip->extractTo($target_dir);
        $zip->close();

        // Update record status
        $wpdb->update($table, ['status' => 'rolled_back'], ['id' => $backup_id]);

        // Re-sync baseline
        WP_ShieldX_File_Monitor::check_integrity();

        return [
            'success' => true,
            'message' => sprintf(__('Successfully rolled back %s from safety snapshot!', 'wp-shieldx'), esc_html($record->item_slug))
        ];
    }

    /**
     * Delete a snapshot
     */
    public static function delete_snapshot($backup_id) {
        global $wpdb;
        $table = WP_ShieldX_Database::get_table_name('backups');
        $record = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE id = %d", $backup_id));

        if ($record && file_exists($record->backup_path)) {
            @unlink($record->backup_path);
        }

        $wpdb->delete($table, ['id' => $backup_id]);
        return ['success' => true, 'message' => __('Snapshot removed from vault.', 'wp-shieldx')];
    }

    /**
     * Get all recorded snapshots
     */
    public static function get_snapshots() {
        global $wpdb;
        $table = WP_ShieldX_Database::get_table_name('backups');
        return $wpdb->get_results("SELECT * FROM $table ORDER BY created_at DESC LIMIT 50");
    }
}
