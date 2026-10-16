<?php
/**
 * WP ShieldX Complete Uninstaller
 * Fired automatically when a user deletes the plugin via WordPress Admin > Plugins > Delete.
 * Performs a 100% clean teardown leaving zero orphaned database tables, files, or .htaccess rules.
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

global $wpdb;

// 1. Clean up root .htaccess hardening block
$htaccess_file = wp_normalize_path(ABSPATH . '.htaccess');
if (file_exists($htaccess_file) && is_writable($htaccess_file)) {
    $content = @file_get_contents($htaccess_file);
    if ($content !== false && strpos($content, '# BEGIN WP ShieldX Hardening') !== false) {
        $cleaned = preg_replace('/# BEGIN WP ShieldX Hardening.*?# END WP ShieldX Hardening\s*/s', '', $content);
        @file_put_contents($htaccess_file, $cleaned);
    }
}

// 2. Clean up uploads lockdown .htaccess
$upload_dir = wp_upload_dir();
$uploads_htaccess = trailingslashit($upload_dir['basedir']) . '.htaccess';
if (file_exists($uploads_htaccess) && is_writable($uploads_htaccess)) {
    $content = @file_get_contents($uploads_htaccess);
    if ($content !== false && strpos($content, '# WP ShieldX Security Uploads Lockdown') !== false) {
        @unlink($uploads_htaccess);
    }
}

// 3. Drop all custom database tables
$tables = [
    $wpdb->prefix . 'wp_shieldx_file_baseline',
    $wpdb->prefix . 'wp_shieldx_scan_results',
    $wpdb->prefix . 'wp_shieldx_firewall_logs',
    $wpdb->prefix . 'wp_shieldx_quarantine',
    $wpdb->prefix . 'wp_shieldx_backups'
];

foreach ($tables as $table) {
    $wpdb->query("DROP TABLE IF EXISTS $table");
}

// 4. Delete plugin settings & options
delete_option('wp_shieldx_settings');
delete_option('wp_shieldx_db_version');

// 5. Delete all transients
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_wp_sec_%' OR option_name LIKE '_transient_timeout_wp_sec_%'");
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_wp_shieldx_%' OR option_name LIKE '_transient_timeout_wp_shieldx_%'");

// 6. Recursively remove quarantine and backup vault directory
$quarantine_dir = trailingslashit($upload_dir['basedir']) . 'wp-shieldx-quarantine/';
if (file_exists($quarantine_dir) && is_dir($quarantine_dir)) {
    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($quarantine_dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($files as $fileinfo) {
        $todo = ($fileinfo->isDir() ? 'rmdir' : 'unlink');
        @$todo($fileinfo->getRealPath());
    }

    @rmdir($quarantine_dir);
}

// 7. Clear any lingering scheduled cron events
$timestamp = wp_next_scheduled('wp_shieldx_scheduled_scan');
if ($timestamp) {
    wp_unschedule_event($timestamp, 'wp_shieldx_scheduled_scan');
}
