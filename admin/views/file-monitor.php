<?php
if (!defined('ABSPATH')) {
    exit;
}

$filter = isset($_GET['filter']) ? sanitize_text_field($_GET['filter']) : 'all';
$files  = WP_ShieldX_File_Monitor::get_changed_files($filter, 100);
$stats  = WP_ShieldX_File_Monitor::get_stats();
?>

<div class="wrap wp-shieldx-wrap">
    <div class="wp-shieldx-header">
        <div class="wp-shieldx-brand">
            <span class="brand-icon">&#128196;</span>
            <div>
                <h1><?php esc_html_e('File Integrity Monitor (FIM)', 'wp-shieldx'); ?></h1>
                <p><?php esc_html_e('Track new, modified, or deleted files across your entire WordPress installation in real-time.', 'wp-shieldx'); ?></p>
            </div>
        </div>
        <div class="header-actions">
            <button id="btn-run-fim" class="wps-btn wps-btn-primary">
                <span class="dashicons dashicons-update"></span> <?php esc_html_e('Scan Integrity Now', 'wp-shieldx'); ?>
            </button>
            <button id="btn-rebuild-baseline" class="wps-btn wps-btn-outline">
                <span class="dashicons dashicons-database-add"></span> <?php esc_html_e('Reset & Rebuild Baseline', 'wp-shieldx'); ?>
            </button>
        </div>
    </div>

    <!-- Filter Navigation Tabs -->
    <div class="wps-filter-tabs">
        <a href="<?php echo esc_url(admin_url('admin.php?page=wp-shieldx-files&filter=all')); ?>" class="tab-item <?php echo $filter === 'all' ? 'active' : ''; ?>">
            <?php esc_html_e('All Changes', 'wp-shieldx'); ?> <span class="tab-count"><?php echo (int)($stats['added'] + $stats['modified'] + $stats['deleted']); ?></span>
        </a>
        <a href="<?php echo esc_url(admin_url('admin.php?page=wp-shieldx-files&filter=added')); ?>" class="tab-item <?php echo $filter === 'added' ? 'active' : ''; ?>">
            <?php esc_html_e('New Files', 'wp-shieldx'); ?> <span class="tab-count count-warning"><?php echo (int)$stats['added']; ?></span>
        </a>
        <a href="<?php echo esc_url(admin_url('admin.php?page=wp-shieldx-files&filter=modified')); ?>" class="tab-item <?php echo $filter === 'modified' ? 'active' : ''; ?>">
            <?php esc_html_e('Modified Files', 'wp-shieldx'); ?> <span class="tab-count count-danger"><?php echo (int)$stats['modified']; ?></span>
        </a>
        <a href="<?php echo esc_url(admin_url('admin.php?page=wp-shieldx-files&filter=deleted')); ?>" class="tab-item <?php echo $filter === 'deleted' ? 'active' : ''; ?>">
            <?php esc_html_e('Deleted Files', 'wp-shieldx'); ?> <span class="tab-count count-muted"><?php echo (int)$stats['deleted']; ?></span>
        </a>
    </div>

    <!-- Files Table -->
    <div class="wps-card">
        <?php if (empty($files)): ?>
            <div class="empty-state">
                <div class="empty-icon">&#10004;</div>
                <h3><?php esc_html_e('Clean State: No Unexpected File Changes', 'wp-shieldx'); ?></h3>
                <p><?php esc_html_e('Every file on your system currently matches the cryptographic baseline snapshot. Any modification or addition will trigger an alert.', 'wp-shieldx'); ?></p>
            </div>
        <?php else: ?>
            <table class="wps-table">
                <thead>
                    <tr>
                        <th style="width: 35%;"><?php esc_html_e('File Path', 'wp-shieldx'); ?></th>
                        <th><?php esc_html_e('Change State', 'wp-shieldx'); ?></th>
                        <th><?php esc_html_e('Size', 'wp-shieldx'); ?></th>
                        <th><?php esc_html_e('SHA-256 Hash', 'wp-shieldx'); ?></th>
                        <th><?php esc_html_e('Last Detected', 'wp-shieldx'); ?></th>
                        <th style="text-align: right;"><?php esc_html_e('Remediation Actions', 'wp-shieldx'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($files as $file): 
                        $is_core = (strpos($file->relative_path, 'wp-content/') !== 0);
                    ?>
                        <tr>
                            <td>
                                <strong><code><?php echo esc_html($file->relative_path); ?></code></strong>
                                <?php if ($is_core): ?>
                                    <span class="badge badge-info" title="Official WordPress Core Directory"><?php esc_html_e('Core File', 'wp-shieldx'); ?></span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ($file->file_status === 'added'): ?>
                                    <span class="badge badge-warning"><?php esc_html_e('NEW FILE', 'wp-shieldx'); ?></span>
                                <?php elseif ($file->file_status === 'modified'): ?>
                                    <span class="badge badge-danger"><?php esc_html_e('MODIFIED', 'wp-shieldx'); ?></span>
                                <?php elseif ($file->file_status === 'deleted'): ?>
                                    <span class="badge badge-muted"><?php esc_html_e('DELETED', 'wp-shieldx'); ?></span>
                                <?php endif; ?>
                            </td>
                            <td><?php echo size_format($file->file_size); ?></td>
                            <td><span class="hash-preview" title="<?php echo esc_attr($file->file_hash); ?>"><?php echo esc_html(substr($file->file_hash, 0, 14)); ?>...</span></td>
                            <td><span class="text-muted"><?php echo esc_html($file->last_scanned); ?></span></td>
                            <td style="text-align: right;">
                                <div class="action-btn-row">
                                    <?php if ($file->file_status !== 'deleted'): ?>
                                        <!-- Quarantine Action -->
                                        <button class="wps-btn-mini wps-btn-warning btn-action-quarantine" data-path="<?php echo esc_attr($file->file_path); ?>" title="<?php esc_attr_e('Move to secure quarantine vault', 'wp-shieldx'); ?>">
                                            <?php esc_html_e('Quarantine', 'wp-shieldx'); ?>
                                        </button>

                                        <!-- Core Repair Action -->
                                        <?php if ($is_core): ?>
                                            <button class="wps-btn-mini wps-btn-info btn-action-repair-core" data-relative="<?php echo esc_attr($file->relative_path); ?>" title="<?php esc_attr_e('Download authentic copy from WordPress.org', 'wp-shieldx'); ?>">
                                                <?php esc_html_e('Repair Core', 'wp-shieldx'); ?>
                                            </button>
                                        <?php endif; ?>

                                        <!-- Whitelist / Accept -->
                                        <button class="wps-btn-mini wps-btn-success btn-action-whitelist" data-path="<?php echo esc_attr($file->file_path); ?>" title="<?php esc_attr_e('Accept change into baseline snapshot', 'wp-shieldx'); ?>">
                                            <?php esc_html_e('Accept', 'wp-shieldx'); ?>
                                        </button>

                                        <!-- Permanent Delete -->
                                        <button class="wps-btn-mini wps-btn-danger btn-action-delete" data-path="<?php echo esc_attr($file->file_path); ?>" title="<?php esc_attr_e('Permanently delete file', 'wp-shieldx'); ?>">
                                            <?php esc_html_e('Delete', 'wp-shieldx'); ?>
                                        </button>
                                    <?php else: ?>
                                        <button class="wps-btn-mini wps-btn-success btn-action-whitelist" data-path="<?php echo esc_attr($file->file_path); ?>" title="<?php esc_attr_e('Accept deletion in baseline', 'wp-shieldx'); ?>">
                                            <?php esc_html_e('Acknowledge', 'wp-shieldx'); ?>
                                        </button>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>
