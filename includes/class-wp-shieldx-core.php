<?php
/**
 * WP ShieldX Core Orchestrator
 */

if (!defined('ABSPATH')) {
    exit;
}

class WP_ShieldX_Core {

    /**
     * Singleton instance
     */
    protected static $instance = null;

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {}

    /**
     * Run plugin functionality
     */
    public function run() {
        // 1. Initialize Active Firewall
        WP_ShieldX_Firewall::init();

        // 2. Initialize Real-Time File Integrity & Upload Interceptors
        WP_ShieldX_File_Monitor::init_realtime_hooks();

        // 3. Initialize 1-Click System Hardening Policies
        WP_ShieldX_Hardening::init();

        // 4. Initialize Pre-Update Auto-Backup Vault
        WP_ShieldX_Backup::init();

        // 5. Register Admin UI & AJAX endpoints
        if (is_admin()) {
            $admin = new WP_ShieldX_Admin();
            $admin->init();
        }

        // 3. Register Cron Tasks
        add_action('wp_shieldx_scheduled_scan', [$this, 'run_scheduled_tasks']);
    }

    /**
     * Scheduled background cron task
     */
    public function run_scheduled_tasks() {
        // 1. Check file modifications/deletions/additions
        WP_ShieldX_File_Monitor::check_integrity();

        // 2. Perform deep malware batch scan
        WP_ShieldX_Malware_Scanner::run_batch_scan(0, 500);
    }
}
