<?php
if (!defined('ABSPATH')) {
    exit;
}

global $wpdb;

$file_stats = WP_ShieldX_File_Monitor::get_stats();

$scan_table = WP_ShieldX_Database::get_table_name('scan_results');
$unresolved_threats = (int)$wpdb->get_var("SELECT COUNT(*) FROM $scan_table WHERE status = 'unresolved'");

$firewall_table = WP_ShieldX_Database::get_table_name('firewall_logs');
$total_attacks = (int)$wpdb->get_var("SELECT COUNT(*) FROM $firewall_table");
$today_attacks = (int)$wpdb->get_var("SELECT COUNT(*) FROM $firewall_table WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");

// Calculate Security Score
$score = 100;
if ($unresolved_threats > 0) $score -= min(40, $unresolved_threats * 15);
if ($file_stats['modified'] > 0 || $file_stats['added'] > 0) $score -= 15;
$score = max(10, $score);

$score_class = 'score-high';
$score_label = __('OPTIMAL PROTECTION', 'wp-shieldx');
if ($score < 70) {
    $score_class = 'score-medium';
    $score_label = __('ATTENTION NEEDED', 'wp-shieldx');
}
if ($score < 50) {
    $score_class = 'score-danger';
    $score_label = __('CRITICAL THREATS DETECTED', 'wp-shieldx');
}

$recent_attacks = $wpdb->get_results("SELECT * FROM $firewall_table ORDER BY created_at DESC LIMIT 6");
$recent_changes = WP_ShieldX_File_Monitor::get_changed_files('all', 6);
?>

<div class="wrap wp-shieldx-wrap">
    <!-- Top Branding Header -->
    <div class="wp-shieldx-header">
        <div class="wp-shieldx-brand">
            <img src="<?php echo esc_url(WP_SHIELDX_URL . 'assets/icon-256x256.svg'); ?>" alt="WP ShieldX" class="brand-logo-img" style="width: 52px; height: 52px; border-radius: 12px; box-shadow: 0 0 15px rgba(56, 189, 248, 0.4);">
            <div>
                <h1>WP ShieldX <span class="badge-version">v<?php echo esc_html(WP_SHIELDX_VERSION); ?></span></h1>
                <p><?php esc_html_e('Advanced WordPress Security, Real-Time File Integrity & Attack Prevention Suite', 'wp-shieldx'); ?></p>
            </div>
        </div>
        <div class="header-actions">
            <button id="btn-quick-check-integrity" class="wps-btn wps-btn-primary">
                <span class="dashicons dashicons-update"></span> <?php esc_html_e('Check File Changes', 'wp-shieldx'); ?>
            </button>
            <a href="<?php echo esc_url(admin_url('admin.php?page=wp-shieldx-scanner')); ?>" class="wps-btn wps-btn-accent">
                <span class="dashicons dashicons-search"></span> <?php esc_html_e('Deep Malware Scan', 'wp-shieldx'); ?>
            </a>
        </div>
    </div>

    <!-- Security Health Banner -->
    <div class="wps-health-card <?php echo esc_attr($score_class); ?>">
        <div class="health-gauge">
            <div class="gauge-value"><?php echo esc_html($score); ?><span>/100</span></div>
            <div class="gauge-label"><?php echo esc_html($score_label); ?></div>
        </div>
        <div class="health-meta">
            <h3><?php esc_html_e('System Security Posture', 'wp-shieldx'); ?></h3>
            <p><?php esc_html_e('Real-time monitoring active. All core system integrity checks, web application firewall filters, and heuristic backdoor shields are operational.', 'wp-shieldx'); ?></p>
            <div class="health-tags">
                <span class="tag tag-ok">&#10004; WAF Active</span>
                <span class="tag tag-ok">&#10004; Integrity Monitor Running</span>
                <span class="tag tag-ok">&#10004; WP Core Checksums Sync</span>
                <span class="tag tag-ok">&#10004; Email Alerts Armed</span>
            </div>
        </div>
    </div>

    <!-- Metric Stat Cards -->
    <div class="wps-grid-4">
        <div class="wps-card wps-stat-card">
            <div class="stat-icon icon-blue">&#128196;</div>
            <div class="stat-body">
                <div class="stat-number"><?php echo number_format($file_stats['total']); ?></div>
                <div class="stat-title"><?php esc_html_e('Monitored Files', 'wp-shieldx'); ?></div>
                <div class="stat-sub"><?php echo number_format($file_stats['clean']); ?> <?php esc_html_e('clean files in baseline', 'wp-shieldx'); ?></div>
            </div>
        </div>

        <div class="wps-card wps-stat-card">
            <div class="stat-icon <?php echo ($file_stats['added'] + $file_stats['modified'] + $file_stats['deleted'] > 0) ? 'icon-amber' : 'icon-green'; ?>">&#128269;</div>
            <div class="stat-body">
                <div class="stat-number"><?php echo number_format($file_stats['added'] + $file_stats['modified'] + $file_stats['deleted']); ?></div>
                <div class="stat-title"><?php esc_html_e('File Changes', 'wp-shieldx'); ?></div>
                <div class="stat-sub">
                    <span class="text-warning">+<?php echo (int)$file_stats['added']; ?> new</span> &bull; 
                    <span class="text-warning">&#9998;<?php echo (int)$file_stats['modified']; ?> modified</span> &bull;
                    <span class="text-danger">&#10008;<?php echo (int)$file_stats['deleted']; ?> deleted</span>
                </div>
            </div>
        </div>

        <div class="wps-card wps-stat-card">
            <div class="stat-icon <?php echo ($unresolved_threats > 0) ? 'icon-red' : 'icon-green'; ?>">&#9760;</div>
            <div class="stat-body">
                <div class="stat-number"><?php echo number_format($unresolved_threats); ?></div>
                <div class="stat-title"><?php esc_html_e('Active Threats', 'wp-shieldx'); ?></div>
                <div class="stat-sub">
                    <?php if ($unresolved_threats > 0): ?>
                        <span class="text-danger"><?php esc_html_e('Immediate remediation advised', 'wp-shieldx'); ?></span>
                    <?php else: ?>
                        <span class="text-success"><?php esc_html_e('No malware detected', 'wp-shieldx'); ?></span>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <div class="wps-card wps-stat-card">
            <div class="stat-icon icon-purple">&#128737;</div>
            <div class="stat-body">
                <div class="stat-number"><?php echo number_format($total_attacks); ?></div>
                <div class="stat-title"><?php esc_html_e('Attacks Blocked', 'wp-shieldx'); ?></div>
                <div class="stat-sub"><?php echo number_format($today_attacks); ?> <?php esc_html_e('blocked in last 24h', 'wp-shieldx'); ?></div>
            </div>
        </div>
    </div>

    <!-- Quick Action Bar -->
    <div class="wps-card wps-quick-actions">
        <h3><?php esc_html_e('Security Actions & Hardening', 'wp-shieldx'); ?></h3>
        <div class="quick-btn-group">
            <button id="btn-rebuild-baseline" class="wps-btn wps-btn-outline">
                <span class="dashicons dashicons-database-add"></span> <?php esc_html_e('Rebuild File Baseline', 'wp-shieldx'); ?>
            </button>
            <button id="btn-lockdown-uploads" class="wps-btn wps-btn-outline">
                <span class="dashicons dashicons-lock"></span> <?php esc_html_e('Lockdown Uploads Directory', 'wp-shieldx'); ?>
            </button>
            <a href="<?php echo esc_url(admin_url('admin.php?page=wp-shieldx-files')); ?>" class="wps-btn wps-btn-outline">
                <span class="dashicons dashicons-visibility"></span> <?php esc_html_e('Review File Changes', 'wp-shieldx'); ?>
            </a>
            <a href="<?php echo esc_url(admin_url('admin.php?page=wp-shieldx-quarantine')); ?>" class="wps-btn wps-btn-outline">
                <span class="dashicons dashicons-archive"></span> <?php esc_html_e('Open Quarantine Vault', 'wp-shieldx'); ?>
            </a>
        </div>
    </div>

    <!-- Two-column Activity Feeds -->
    <div class="wps-grid-2">
        <!-- Recent Blocked Attacks -->
        <div class="wps-card">
            <div class="card-head">
                <h3>&#128737; <?php esc_html_e('Recent Blocked Attacks', 'wp-shieldx'); ?></h3>
                <a href="<?php echo esc_url(admin_url('admin.php?page=wp-shieldx-firewall')); ?>" class="link-more"><?php esc_html_e('View All Logs &rarr;', 'wp-shieldx'); ?></a>
            </div>
            <?php if (empty($recent_attacks)): ?>
                <div class="empty-state">&#10004; <?php esc_html_e('No attacks recorded yet. Firewall is standing guard.', 'wp-shieldx'); ?></div>
            <?php else: ?>
                <table class="wps-table">
                    <thead>
                        <tr>
                            <th><?php esc_html_e('Time', 'wp-shieldx'); ?></th>
                            <th><?php esc_html_e('Threat Type', 'wp-shieldx'); ?></th>
                            <th><?php esc_html_e('IP Address', 'wp-shieldx'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recent_attacks as $attack): ?>
                            <tr>
                                <td><span class="text-muted"><?php echo esc_html(human_time_diff(strtotime($attack->created_at), current_time('timestamp'))); ?> ago</span></td>
                                <td><span class="badge badge-threat"><?php echo esc_html($attack->attack_type); ?></span></td>
                                <td><code><?php echo esc_html($attack->ip_address); ?></code></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>

        <!-- Recent File Changes -->
        <div class="wps-card">
            <div class="card-head">
                <h3>&#128196; <?php esc_html_e('Recent File Integrity Alerts', 'wp-shieldx'); ?></h3>
                <a href="<?php echo esc_url(admin_url('admin.php?page=wp-shieldx-files')); ?>" class="link-more"><?php esc_html_e('Review Changes &rarr;', 'wp-shieldx'); ?></a>
            </div>
            <?php if (empty($recent_changes)): ?>
                <div class="empty-state">&#10004; <?php esc_html_e('All monitored files match the trusted baseline snapshot.', 'wp-shieldx'); ?></div>
            <?php else: ?>
                <table class="wps-table">
                    <thead>
                        <tr>
                            <th><?php esc_html_e('File Path', 'wp-shieldx'); ?></th>
                            <th><?php esc_html_e('Change Type', 'wp-shieldx'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recent_changes as $ch): ?>
                            <tr>
                                <td><code><?php echo esc_html($ch->relative_path); ?></code></td>
                                <td>
                                    <?php if ($ch->file_status === 'added'): ?>
                                        <span class="badge badge-warning"><?php esc_html_e('NEW FILE', 'wp-shieldx'); ?></span>
                                    <?php elseif ($ch->file_status === 'modified'): ?>
                                        <span class="badge badge-danger"><?php esc_html_e('MODIFIED', 'wp-shieldx'); ?></span>
                                    <?php else: ?>
                                        <span class="badge badge-muted"><?php echo esc_html(strtoupper($ch->file_status)); ?></span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </div>

    <!-- Developer Attribution Footer -->
    <div class="wps-card wps-dev-footer" style="display: flex; justify-content: space-between; align-items: center; padding: 16px 24px; background: #0f172a; color: #94a3b8; border: 1px solid #1e293b; border-radius: 8px;">
        <div>
            <strong style="color: #f8fafc;">WP ShieldX Security Suite</strong> &bull; <?php esc_html_e('Next-Gen Cyber Defense & File Integrity', 'wp-shieldx'); ?>
        </div>
        <div>
            <?php esc_html_e('Developed with precision by', 'wp-shieldx'); ?> 
            <a href="https://www.saiarlen.com" target="_blank" rel="noopener noreferrer" style="color: #38bdf8; font-weight: 700; text-decoration: none;">saiarlen</a> &bull; 
            <a href="https://www.saiarlen.com" target="_blank" rel="noopener noreferrer" style="color: #cbd5e1; text-decoration: none;">www.saiarlen.com</a>
        </div>
    </div>
</div>
