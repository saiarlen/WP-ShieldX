<?php
/**
 * WP ShieldX Database Manager
 * Handles schema installation, updates, and query helpers.
 */

if (!defined('ABSPATH')) {
    exit;
}

class WP_ShieldX_Database {

    /**
     * Get table names
     */
    public static function get_table_name($table) {
        global $wpdb;
        return $wpdb->prefix . 'wp_shieldx_' . $table;
    }

    /**
     * Create or upgrade plugin database tables
     */
    public static function create_tables() {
        global $wpdb;

        $charset_collate = $wpdb->get_charset_collate();

        $baseline_table   = self::get_table_name('file_baseline');
        $scan_table       = self::get_table_name('scan_results');
        $firewall_table   = self::get_table_name('firewall_logs');
        $quarantine_table = self::get_table_name('quarantine');

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');

        // 1. File Baseline Table
        $sql_baseline = "CREATE TABLE $baseline_table (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            file_path VARCHAR(500) NOT NULL,
            relative_path VARCHAR(255) NOT NULL,
            file_hash VARCHAR(64) NOT NULL,
            file_size BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
            file_mtime INT(11) UNSIGNED NOT NULL DEFAULT 0,
            file_status VARCHAR(20) NOT NULL DEFAULT 'clean',
            last_scanned DATETIME NOT NULL,
            PRIMARY KEY (id),
            KEY relative_path (relative_path),
            KEY file_status (file_status)
        ) $charset_collate;";
        dbDelta($sql_baseline);

        // 2. Scan Results / Threats Table
        $sql_scan = "CREATE TABLE $scan_table (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            file_path VARCHAR(500) NOT NULL,
            relative_path VARCHAR(255) NOT NULL,
            threat_type VARCHAR(50) NOT NULL,
            threat_name VARCHAR(100) NOT NULL,
            severity VARCHAR(20) NOT NULL DEFAULT 'high',
            line_number INT(11) NOT NULL DEFAULT 0,
            match_snippet TEXT,
            status VARCHAR(20) NOT NULL DEFAULT 'unresolved',
            detected_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            KEY status (status),
            KEY severity (severity),
            KEY relative_path (relative_path)
        ) $charset_collate;";
        dbDelta($sql_scan);

        // 3. Firewall Logs Table
        $sql_firewall = "CREATE TABLE $firewall_table (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_address VARCHAR(45) NOT NULL,
            request_uri TEXT NOT NULL,
            request_method VARCHAR(10) NOT NULL DEFAULT 'GET',
            user_agent TEXT,
            attack_type VARCHAR(50) NOT NULL,
            payload TEXT,
            action_taken VARCHAR(20) NOT NULL DEFAULT 'blocked',
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY attack_type (attack_type),
            KEY created_at (created_at)
        ) $charset_collate;";
        dbDelta($sql_firewall);

        // 4. Quarantine Vault Table
        $sql_quarantine = "CREATE TABLE $quarantine_table (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            original_path VARCHAR(500) NOT NULL,
            quarantined_path VARCHAR(500) NOT NULL,
            file_hash VARCHAR(64) NOT NULL,
            file_size BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
            permissions VARCHAR(10) NOT NULL DEFAULT '0644',
            quarantined_at DATETIME NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'quarantined',
            PRIMARY KEY (id),
            KEY status (status)
        ) $charset_collate;";
        dbDelta($sql_quarantine);

        // 5. Auto-Backup Rollback Snapshots Table
        $backups_table = self::get_table_name('backups');
        $sql_backups = "CREATE TABLE $backups_table (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            item_type VARCHAR(20) NOT NULL DEFAULT 'plugin',
            item_slug VARCHAR(100) NOT NULL,
            backup_path VARCHAR(500) NOT NULL,
            file_size BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'ready',
            PRIMARY KEY (id),
            KEY item_slug (item_slug),
            KEY status (status)
        ) $charset_collate;";
        dbDelta($sql_backups);

        update_option('wp_shieldx_db_version', WP_SHIELDX_VERSION);
    }
}
