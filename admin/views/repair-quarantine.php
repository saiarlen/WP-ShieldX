<?php
if (!defined('ABSPATH')) {
    exit;
}

global $wpdb;
$table = WP_ShieldX_Database::get_table_name('quarantine');
$items = $wpdb->get_results("SELECT * FROM $table WHERE status = 'quarantined' ORDER BY quarantined_at DESC");
?>

<div class="wrap wp-shieldx-wrap">
    <div class="wp-shieldx-header">
        <div class="wp-shieldx-brand">
            <span class="brand-icon">&#128272;</span>
            <div>
                <h1><?php esc_html_e('Quarantine Vault & Repair Station', 'wp-shieldx'); ?></h1>
                <p><?php esc_html_e('Isolated storage vault for malicious or modified files with disabled permissions, plus instant WordPress.org core file repair.', 'wp-shieldx'); ?></p>
            </div>
        </div>
    </div>

    <!-- On-Demand WordPress Core Repair Utility -->
    <div class="wps-card wps-repair-banner">
        <div class="repair-intro">
            <h3>&#128736; <?php esc_html_e('WordPress.org Official Core File Repair', 'wp-shieldx'); ?></h3>
            <p><?php esc_html_e('If an official WordPress core file was tampered with, injected, or corrupted, enter its relative path below to automatically backup the damaged file and overwrite it with the authentic, verified pristine copy directly from WordPress.org releases.', 'wp-shieldx'); ?></p>
        </div>
        <div class="repair-form-inline">
            <input type="text" id="manual-repair-path" class="wps-input" placeholder="e.g. wp-login.php or wp-includes/pluggable.php" style="max-width: 400px;">
            <button id="btn-manual-repair" class="wps-btn wps-btn-accent">
                <span class="dashicons dashicons-update"></span> <?php esc_html_e('Download Clean Copy & Repair', 'wp-shieldx'); ?>
            </button>
        </div>
    </div>

    <!-- Quarantine Vault Table -->
    <div class="wps-card">
        <div class="card-head">
            <h3>&#128451; <?php esc_html_e('Quarantined Files Vault', 'wp-shieldx'); ?> <span class="badge badge-warning"><?php echo count($items); ?></span></h3>
        </div>

        <?php if (empty($items)): ?>
            <div class="empty-state">
                <div class="empty-icon text-success">&#10004;</div>
                <h3><?php esc_html_e('Quarantine Vault is Empty', 'wp-shieldx'); ?></h3>
                <p><?php esc_html_e('No files are currently quarantined. When suspicious files or webshells are quarantined, they are safely relocated to this encrypted vault with execution privileges revoked.', 'wp-shieldx'); ?></p>
            </div>
        <?php else: ?>
            <table class="wps-table">
                <thead>
                    <tr>
                        <th style="width: 35%;"><?php esc_html_e('Original File Path', 'wp-shieldx'); ?></th>
                        <th><?php esc_html_e('Quarantined Date', 'wp-shieldx'); ?></th>
                        <th><?php esc_html_e('File Size', 'wp-shieldx'); ?></th>
                        <th><?php esc_html_e('SHA-256 Hash', 'wp-shieldx'); ?></th>
                        <th style="text-align: right;"><?php esc_html_e('Remediation', 'wp-shieldx'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($items as $item): ?>
                        <tr>
                            <td><code><?php echo esc_html($item->original_path); ?></code></td>
                            <td><span class="text-muted"><?php echo esc_html($item->quarantined_at); ?></span></td>
                            <td><?php echo size_format($item->file_size); ?></td>
                            <td><span class="hash-preview" title="<?php echo esc_attr($item->file_hash); ?>"><?php echo esc_html(substr($item->file_hash, 0, 16)); ?>...</span></td>
                            <td style="text-align: right;">
                                <div class="action-btn-row">
                                    <button class="wps-btn-mini wps-btn-success btn-action-restore" data-id="<?php echo esc_attr($item->id); ?>" title="<?php esc_attr_e('Restore file back to original path', 'wp-shieldx'); ?>">
                                        <?php esc_html_e('Restore', 'wp-shieldx'); ?>
                                    </button>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <!-- Auto-Backup Snapshots & Rollback Vault -->
    <?php
    $backups = WP_ShieldX_Backup::get_snapshots();
    ?>
    <div class="wps-card">
        <div class="card-head">
            <h3>&#128190; <?php esc_html_e('Pre-Update Safety Snapshots (1-Click Rollback Vault)', 'wp-shieldx'); ?> <span class="badge badge-info"><?php echo count($backups); ?></span></h3>
        </div>
        <p class="description" style="margin-bottom: 16px;"><?php esc_html_e('Before any plugin or theme update is applied, WP ShieldX captures a compressed safety snapshot here. If an update breaks your site or includes bugs, click Rollback to instantly restore the previous version.', 'wp-shieldx'); ?></p>

        <?php if (empty($backups)): ?>
            <div class="empty-state">
                <div class="empty-icon text-muted">&#128190;</div>
                <h3><?php esc_html_e('No Update Snapshots Yet', 'wp-shieldx'); ?></h3>
                <p><?php esc_html_e('Snapshots are automatically generated when you update plugins or themes in WordPress.', 'wp-shieldx'); ?></p>
            </div>
        <?php else: ?>
            <table class="wps-table">
                <thead>
                    <tr>
                        <th style="width: 25%;"><?php esc_html_e('Extension Slug', 'wp-shieldx'); ?></th>
                        <th><?php esc_html_e('Type', 'wp-shieldx'); ?></th>
                        <th><?php esc_html_e('Snapshot Date', 'wp-shieldx'); ?></th>
                        <th><?php esc_html_e('Archive Size', 'wp-shieldx'); ?></th>
                        <th><?php esc_html_e('Status', 'wp-shieldx'); ?></th>
                        <th style="text-align: right;"><?php esc_html_e('Action', 'wp-shieldx'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($backups as $b): ?>
                        <tr>
                            <td><strong><code><?php echo esc_html($b->item_slug); ?></code></strong></td>
                            <td><span class="badge badge-info"><?php echo esc_html(strtoupper($b->item_type)); ?></span></td>
                            <td><span class="text-muted"><?php echo esc_html($b->created_at); ?></span></td>
                            <td><?php echo size_format($b->file_size); ?></td>
                            <td>
                                <?php if ($b->status === 'rolled_back'): ?>
                                    <span class="badge badge-warning"><?php esc_html_e('ROLLED BACK', 'wp-shieldx'); ?></span>
                                <?php else: ?>
                                    <span class="badge badge-success"><?php esc_html_e('READY', 'wp-shieldx'); ?></span>
                                <?php endif; ?>
                            </td>
                            <td style="text-align: right;">
                                <div class="action-btn-row">
                                    <button class="wps-btn-mini wps-btn-primary btn-action-rollback" data-id="<?php echo esc_attr($b->id); ?>" title="<?php esc_attr_e('Rollback extension to this snapshot', 'wp-shieldx'); ?>">
                                        <?php esc_html_e('1-Click Rollback', 'wp-shieldx'); ?>
                                    </button>
                                    <button class="wps-btn-mini wps-btn-danger btn-action-delete-backup" data-id="<?php echo esc_attr($b->id); ?>" title="<?php esc_attr_e('Delete backup archive', 'wp-shieldx'); ?>">
                                        <?php esc_html_e('Delete', 'wp-shieldx'); ?>
                                    </button>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>
