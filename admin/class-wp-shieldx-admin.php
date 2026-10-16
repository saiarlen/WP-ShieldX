<?php
/**
 * WP ShieldX Admin Controller
 * Manages WordPress admin menu, views, AJAX handlers, and security actions.
 */

if (!defined('ABSPATH')) {
    exit;
}

class WP_ShieldX_Admin {

    public function init() {
        add_action('admin_menu', [$this, 'register_admin_menus']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_assets']);

        // AJAX handlers
        $ajax_actions = [
            'rebuild_baseline',
            'check_integrity',
            'run_malware_scan',
            'quarantine_file',
            'restore_quarantined',
            'repair_core',
            'delete_file',
            'whitelist_file',
            'lockdown_uploads',
            'clear_firewall_logs',
            'clear_scan_results',
            'scan_database',
            'clean_db_record',
            'audit_plugins',
            'rollback_backup',
            'delete_backup',
            'save_hardening',
            'save_settings'
        ];

        foreach ($ajax_actions as $action) {
            add_action('wp_ajax_wp_shieldx_' . $action, [$this, 'ajax_' . $action]);
        }
    }

    /**
     * Register Admin Menus
     */
    public function register_admin_menus() {
        add_menu_page(
            __('WP ShieldX Security', 'wp-shieldx'),
            __('WP ShieldX', 'wp-shieldx'),
            'manage_options',
            'wp-shieldx',
            [$this, 'render_dashboard'],
            'dashicons-shield',
            80
        );

        add_submenu_page(
            'wp-shieldx',
            __('Dashboard & Health', 'wp-shieldx'),
            __('Dashboard', 'wp-shieldx'),
            'manage_options',
            'wp-shieldx',
            [$this, 'render_dashboard']
        );

        add_submenu_page(
            'wp-shieldx',
            __('File Integrity Monitor', 'wp-shieldx'),
            __('File Monitor', 'wp-shieldx'),
            'manage_options',
            'wp-shieldx-files',
            [$this, 'render_file_monitor']
        );

        add_submenu_page(
            'wp-shieldx',
            __('Deep Malware Scanner', 'wp-shieldx'),
            __('Malware Scanner', 'wp-shieldx'),
            'manage_options',
            'wp-shieldx-scanner',
            [$this, 'render_malware_scanner']
        );

        add_submenu_page(
            'wp-shieldx',
            __('Database Threat & SEO Scanner', 'wp-shieldx'),
            __('DB Threat Scanner', 'wp-shieldx'),
            'manage_options',
            'wp-shieldx-db',
            [$this, 'render_db_scanner']
        );

        add_submenu_page(
            'wp-shieldx',
            __('Plugin Vulnerability Audit', 'wp-shieldx'),
            __('Vulnerable Plugins', 'wp-shieldx'),
            'manage_options',
            'wp-shieldx-vuln',
            [$this, 'render_vulnerability_audit']
        );

        add_submenu_page(
            'wp-shieldx',
            __('1-Click System Hardening', 'wp-shieldx'),
            __('System Hardening', 'wp-shieldx'),
            'manage_options',
            'wp-shieldx-hardening',
            [$this, 'render_hardening']
        );

        add_submenu_page(
            'wp-shieldx',
            __('Firewall & Attack Logs', 'wp-shieldx'),
            __('Firewall & Logs', 'wp-shieldx'),
            'manage_options',
            'wp-shieldx-firewall',
            [$this, 'render_firewall']
        );

        add_submenu_page(
            'wp-shieldx',
            __('Quarantine Vault & Rollbacks', 'wp-shieldx'),
            __('Quarantine & Rollback', 'wp-shieldx'),
            'manage_options',
            'wp-shieldx-quarantine',
            [$this, 'render_quarantine']
        );

        add_submenu_page(
            'wp-shieldx',
            __('Security Settings', 'wp-shieldx'),
            __('Settings', 'wp-shieldx'),
            'manage_options',
            'wp-shieldx-settings',
            [$this, 'render_settings']
        );
    }

    /**
     * Enqueue Admin CSS & JS
     */
    public function enqueue_admin_assets($hook) {
        if (strpos($hook, 'wp-shieldx') === false) {
            return;
        }

        wp_enqueue_style(
            'wp-shieldx-admin-css',
            WP_SHIELDX_URL . 'admin/css/wp-shieldx-admin.css',
            [],
            WP_SHIELDX_VERSION
        );

        wp_enqueue_script(
            'wp-shieldx-admin-js',
            WP_SHIELDX_URL . 'admin/js/wp-shieldx-admin.js',
            ['jquery'],
            WP_SHIELDX_VERSION,
            true
        );

        wp_localize_script('wp-shieldx-admin-js', 'wpShieldXData', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce'    => wp_create_nonce('wp_shieldx_admin_nonce'),
            'strings'  => [
                'confirm_quarantine' => __('Are you sure you want to quarantine this file?', 'wp-shieldx'),
                'confirm_delete'     => __('Warning: This will permanently delete the file. Proceed?', 'wp-shieldx'),
                'confirm_repair'     => __('This will download and replace the file with the official WordPress.org copy. Proceed?', 'wp-shieldx'),
                'scanning'           => __('Scanning in progress...', 'wp-shieldx'),
                'scan_complete'      => __('Scan complete!', 'wp-shieldx')
            ]
        ]);
    }

    // View Renderers
    public function render_dashboard() {
        include WP_SHIELDX_PATH . 'admin/views/dashboard.php';
    }

    public function render_file_monitor() {
        include WP_SHIELDX_PATH . 'admin/views/file-monitor.php';
    }

    public function render_malware_scanner() {
        include WP_SHIELDX_PATH . 'admin/views/malware-scanner.php';
    }

    public function render_db_scanner() {
        include WP_SHIELDX_PATH . 'admin/views/db-scanner.php';
    }

    public function render_vulnerability_audit() {
        include WP_SHIELDX_PATH . 'admin/views/vulnerability-audit.php';
    }

    public function render_hardening() {
        include WP_SHIELDX_PATH . 'admin/views/hardening.php';
    }

    public function render_firewall() {
        include WP_SHIELDX_PATH . 'admin/views/firewall.php';
    }

    public function render_quarantine() {
        include WP_SHIELDX_PATH . 'admin/views/repair-quarantine.php';
    }

    public function render_settings() {
        include WP_SHIELDX_PATH . 'admin/views/settings.php';
    }

    // AJAX Handlers
    protected function verify_ajax() {
        check_ajax_referer('wp_shieldx_admin_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'wp-shieldx')]);
        }
    }

    public function ajax_rebuild_baseline() {
        $this->verify_ajax();
        $count = WP_ShieldX_File_Monitor::build_baseline();
        wp_send_json_success(['message' => sprintf(__('File baseline rebuilt successfully with %d files indexed.', 'wp-shieldx'), $count)]);
    }

    public function ajax_check_integrity() {
        $this->verify_ajax();
        $results = WP_ShieldX_File_Monitor::check_integrity();
        wp_send_json_success($results);
    }

    public function ajax_run_malware_scan() {
        $this->verify_ajax();
        $offset = isset($_POST['offset']) ? intval($_POST['offset']) : 0;
        $limit  = isset($_POST['limit']) ? intval($_POST['limit']) : 50;

        $results = WP_ShieldX_Malware_Scanner::run_batch_scan($offset, $limit);
        wp_send_json_success($results);
    }

    public function ajax_quarantine_file() {
        $this->verify_ajax();
        $path = isset($_POST['file_path']) ? sanitize_text_field(wp_unslash($_POST['file_path'])) : '';
        $res  = WP_ShieldX_Repair::quarantine_file($path);
        if ($res['success']) {
            wp_send_json_success($res);
        } else {
            wp_send_json_error($res);
        }
    }

    public function ajax_restore_quarantined() {
        $this->verify_ajax();
        $id  = isset($_POST['quarantine_id']) ? intval($_POST['quarantine_id']) : 0;
        $res = WP_ShieldX_Repair::restore_quarantined_file($id);
        if ($res['success']) {
            wp_send_json_success($res);
        } else {
            wp_send_json_error($res);
        }
    }

    public function ajax_repair_core() {
        $this->verify_ajax();
        $relative = isset($_POST['relative_path']) ? sanitize_text_field(wp_unslash($_POST['relative_path'])) : '';
        $res = WP_ShieldX_Repair::repair_core_file($relative);
        if ($res['success']) {
            wp_send_json_success($res);
        } else {
            wp_send_json_error($res);
        }
    }

    public function ajax_delete_file() {
        $this->verify_ajax();
        $path = isset($_POST['file_path']) ? sanitize_text_field(wp_unslash($_POST['file_path'])) : '';
        $res  = WP_ShieldX_Repair::delete_file($path);
        if ($res['success']) {
            wp_send_json_success($res);
        } else {
            wp_send_json_error($res);
        }
    }

    public function ajax_whitelist_file() {
        $this->verify_ajax();
        $path = isset($_POST['file_path']) ? sanitize_text_field(wp_unslash($_POST['file_path'])) : '';
        $res  = WP_ShieldX_Repair::whitelist_file($path);
        if ($res['success']) {
            wp_send_json_success($res);
        } else {
            wp_send_json_error($res);
        }
    }

    public function ajax_lockdown_uploads() {
        $this->verify_ajax();
        $res = WP_ShieldX_Repair::lockdown_uploads_folder();
        if ($res['success']) {
            wp_send_json_success($res);
        } else {
            wp_send_json_error($res);
        }
    }

    public function ajax_clear_firewall_logs() {
        $this->verify_ajax();
        global $wpdb;
        $table = WP_ShieldX_Database::get_table_name('firewall_logs');
        $wpdb->query("TRUNCATE TABLE $table");
        wp_send_json_success(['message' => __('Firewall logs cleared.', 'wp-shieldx')]);
    }

    public function ajax_clear_scan_results() {
        $this->verify_ajax();
        WP_ShieldX_Malware_Scanner::reset_results();
        wp_send_json_success(['message' => __('Scan findings cleared.', 'wp-shieldx')]);
    }

    public function ajax_save_settings() {
        $this->verify_ajax();
        
        $settings = [
            'waf_enabled'           => !empty($_POST['waf_enabled']) ? 1 : 0,
            'disable_xmlrpc'        => !empty($_POST['disable_xmlrpc']) ? 1 : 0,
            'email_notifications'   => !empty($_POST['email_notifications']) ? 1 : 0,
            'alert_email'           => sanitize_email($_POST['alert_email']),
            'notify_on_firewall'    => !empty($_POST['notify_on_firewall']) ? 1 : 0,
            'notify_on_file_change' => !empty($_POST['notify_on_file_change']) ? 1 : 0,
            'notify_on_malware'     => !empty($_POST['notify_on_malware']) ? 1 : 0,
            'scan_frequency'        => sanitize_text_field($_POST['scan_frequency']),
            'ip_whitelist'          => sanitize_textarea_field($_POST['ip_whitelist']),
            'ip_blacklist'          => sanitize_textarea_field($_POST['ip_blacklist'])
        ];

        update_option('wp_shieldx_settings', $settings);
        wp_send_json_success(['message' => __('Security settings saved successfully!', 'wp-shieldx')]);
    }

    public function ajax_scan_database() {
        $this->verify_ajax();
        $findings = WP_ShieldX_DB_Scanner::scan_database();
        wp_send_json_success(['findings' => $findings]);
    }

    public function ajax_clean_db_record() {
        $this->verify_ajax();
        $table     = isset($_POST['table_name']) ? sanitize_text_field($_POST['table_name']) : '';
        $record_id = isset($_POST['record_id']) ? intval($_POST['record_id']) : 0;
        $field     = isset($_POST['field']) ? sanitize_text_field($_POST['field']) : '';
        $snippet   = isset($_POST['snippet']) ? wp_unslash($_POST['snippet']) : '';
        $res = WP_ShieldX_DB_Scanner::clean_record($table, $record_id, $field, $snippet);
        if ($res['success']) {
            wp_send_json_success($res);
        } else {
            wp_send_json_error($res);
        }
    }

    public function ajax_audit_plugins() {
        $this->verify_ajax();
        $refresh = !empty($_POST['refresh']);
        $results = WP_ShieldX_Vulnerability_Auditor::audit_plugins($refresh);
        wp_send_json_success(['plugins' => $results]);
    }

    public function ajax_rollback_backup() {
        $this->verify_ajax();
        $id = isset($_POST['backup_id']) ? intval($_POST['backup_id']) : 0;
        $res = WP_ShieldX_Backup::rollback_snapshot($id);
        if ($res['success']) {
            wp_send_json_success($res);
        } else {
            wp_send_json_error($res);
        }
    }

    public function ajax_delete_backup() {
        $this->verify_ajax();
        $id = isset($_POST['backup_id']) ? intval($_POST['backup_id']) : 0;
        $res = WP_ShieldX_Backup::delete_snapshot($id);
        wp_send_json_success($res);
    }

    public function ajax_save_hardening() {
        $this->verify_ajax();
        $settings = get_option('wp_shieldx_settings', []);
        $settings['harden_disable_file_edit']         = !empty($_POST['harden_disable_file_edit']) ? 1 : 0;
        $settings['harden_hide_wp_version']            = !empty($_POST['harden_hide_wp_version']) ? 1 : 0;
        $settings['harden_disable_directory_browsing'] = !empty($_POST['harden_disable_directory_browsing']) ? 1 : 0;
        $settings['harden_disable_app_passwords']      = !empty($_POST['harden_disable_app_passwords']) ? 1 : 0;
        $settings['harden_protect_wp_config']          = !empty($_POST['harden_protect_wp_config']) ? 1 : 0;

        update_option('wp_shieldx_settings', $settings);
        WP_ShieldX_Hardening::sync_htaccess_rules($settings);
        wp_send_json_success(['message' => __('Hardening security policies successfully enforced!', 'wp-shieldx')]);
    }
}
