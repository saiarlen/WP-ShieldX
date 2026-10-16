<?php
if (!defined('ABSPATH')) {
    exit;
}

global $wpdb;
$table = WP_ShieldX_Database::get_table_name('firewall_logs');
$logs  = $wpdb->get_results("SELECT * FROM $table ORDER BY created_at DESC LIMIT 100");
$total = (int)$wpdb->get_var("SELECT COUNT(*) FROM $table");
?>

<div class="wrap wp-shieldx-wrap">
    <div class="wp-shieldx-header">
        <div class="wp-shieldx-brand">
            <span class="brand-icon">&#128737;</span>
            <div>
                <h1><?php esc_html_e('Firewall & Attack Prevention Center', 'wp-shieldx'); ?></h1>
                <p><?php esc_html_e('Multi-layer Web Application Firewall (WAF) blocking malicious requests before they reach your WordPress themes or database.', 'wp-shieldx'); ?></p>
            </div>
        </div>
        <div class="header-actions">
            <button id="btn-clear-firewall-logs" class="wps-btn wps-btn-outline">
                <span class="dashicons dashicons-trash"></span> <?php esc_html_e('Clear Attack Logs', 'wp-shieldx'); ?>
            </button>
            <a href="<?php echo esc_url(admin_url('admin.php?page=wp-shieldx-settings')); ?>" class="wps-btn wps-btn-primary">
                <span class="dashicons dashicons-admin-settings"></span> <?php esc_html_e('Firewall Rules & IP Lists', 'wp-shieldx'); ?>
            </a>
        </div>
    </div>

    <!-- Active Shield Modules -->
    <div class="wps-grid-3">
        <div class="wps-card wps-shield-card">
            <div class="shield-title">&#9889; <?php esc_html_e('Input & Query Injection Defense', 'wp-shieldx'); ?></div>
            <p><?php esc_html_e('Blocks UNION SELECT, benchmark/sleep blind SQLi, stored/reflected XSS script payloads, and HTML injection.', 'wp-shieldx'); ?></p>
            <span class="badge badge-success">&#10004; <?php esc_html_e('Active & Filtering', 'wp-shieldx'); ?></span>
        </div>
        <div class="wps-card wps-shield-card">
            <div class="shield-title">&#128274; <?php esc_html_e('Directory & Traversal Defense', 'wp-shieldx'); ?></div>
            <p><?php esc_html_e('Stops ../ path traversal, /etc/passwd LFI, PHP input/filter streams, and sensitive file probing (.env, .git, .sql).', 'wp-shieldx'); ?></p>
            <span class="badge badge-success">&#10004; <?php esc_html_e('Active & Filtering', 'wp-shieldx'); ?></span>
        </div>
        <div class="wps-card wps-shield-card">
            <div class="shield-title">&#129302; <?php esc_html_e('Bad Bot & Enumeration Shield', 'wp-shieldx'); ?></div>
            <p><?php esc_html_e('Blocks automated attack scanners (sqlmap, nikto, wpscan) and halts /?author=1 username enumeration.', 'wp-shieldx'); ?></p>
            <span class="badge badge-success">&#10004; <?php esc_html_e('Active & Filtering', 'wp-shieldx'); ?></span>
        </div>
    </div>

    <!-- Live Firewall Logs -->
    <div class="wps-card">
        <div class="card-head">
            <h3>&#128737; <?php esc_html_e('Real-Time Attack Log History', 'wp-shieldx'); ?> <span class="badge badge-threat"><?php echo esc_html($total); ?></span></h3>
        </div>

        <?php if (empty($logs)): ?>
            <div class="empty-state">
                <div class="empty-icon text-success">&#10004;</div>
                <h3><?php esc_html_e('No Malicious Requests Blocked Yet', 'wp-shieldx'); ?></h3>
                <p><?php esc_html_e('The firewall is monitoring all incoming GET, POST, COOKIE, and URI vectors. Any hostile payload will be blocked and recorded here.', 'wp-shieldx'); ?></p>
            </div>
        <?php else: ?>
            <table class="wps-table">
                <thead>
                    <tr>
                        <th style="width: 14%;"><?php esc_html_e('Date / Time', 'wp-shieldx'); ?></th>
                        <th style="width: 12%;"><?php esc_html_e('Attack Vector', 'wp-shieldx'); ?></th>
                        <th style="width: 14%;"><?php esc_html_e('Attacker IP', 'wp-shieldx'); ?></th>
                        <th style="width: 25%;"><?php esc_html_e('Request URI', 'wp-shieldx'); ?></th>
                        <th style="width: 25%;"><?php esc_html_e('Blocked Payload / Reason', 'wp-shieldx'); ?></th>
                        <th style="text-align: right;"><?php esc_html_e('Action', 'wp-shieldx'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($logs as $log): ?>
                        <tr>
                            <td><span class="text-muted"><?php echo esc_html($log->created_at); ?></span></td>
                            <td><span class="badge badge-threat"><?php echo esc_html($log->attack_type); ?></span></td>
                            <td><code><?php echo esc_html($log->ip_address); ?></code></td>
                            <td><span class="uri-path" title="<?php echo esc_attr($log->request_uri); ?>"><?php echo esc_html($log->request_method . ' ' . substr($log->request_uri, 0, 45)); ?></span></td>
                            <td><code class="payload-preview"><?php echo esc_html(substr($log->payload, 0, 80)); ?></code></td>
                            <td style="text-align: right;">
                                <span class="badge badge-danger"><?php echo esc_html(strtoupper($log->action_taken)); ?></span>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>
