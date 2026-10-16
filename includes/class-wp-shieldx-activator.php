<?php
/**
 * WP ShieldX Plugin Activator
 */

if (!defined('ABSPATH')) {
    exit;
}

class WP_ShieldX_Activator {

    public static function activate() {
        // 1. Create custom tables
        WP_ShieldX_Database::create_tables();

        // 2. Initialize default options
        $default_settings = [
            'waf_enabled'           => 1,
            'disable_xmlrpc'        => 1,
            'email_notifications'   => 1,
            'alert_email'           => get_option('admin_email'),
            'notify_on_firewall'    => 1,
            'notify_on_file_change' => 1,
            'notify_on_malware'     => 1,
            'scan_frequency'        => 'daily',
            'ip_whitelist'          => "127.0.0.1\n::1",
            'ip_blacklist'          => ''
        ];

        if (!get_option('wp_shieldx_settings')) {
            update_option('wp_shieldx_settings', $default_settings);
        }

        // 3. Ensure Quarantine vault exists with .htaccess shield
        WP_ShieldX_Repair::get_quarantine_dir();

        // 4. Schedule cron event for periodic file integrity check & malware scan
        if (!wp_next_scheduled('wp_shieldx_scheduled_scan')) {
            wp_schedule_event(time() + 60, 'daily', 'wp_shieldx_scheduled_scan');
        }

        // 5. Build initial baseline in background if table is empty
        global $wpdb;
        $table = WP_ShieldX_Database::get_table_name('file_baseline');
        $count = $wpdb->get_var("SELECT COUNT(*) FROM $table");
        if ((int)$count === 0) {
            WP_ShieldX_File_Monitor::build_baseline();
        }
    }
}
