<?php
if (!defined('ABSPATH')) {
    exit;
}
?>

<div class="wrap wp-shieldx-wrap">
    <div class="wp-shieldx-header">
        <div class="wp-shieldx-brand">
            <span class="brand-icon">&#128450;</span>
            <div>
                <h1><?php esc_html_e('Database Threat & SEO Spam Scanner', 'wp-shieldx'); ?></h1>
                <p><?php esc_html_e('Scans database tables (posts, options, comments) for injected JavaScript tags, hidden iframes, base64 data payloads, and SEO redirects.', 'wp-shieldx'); ?></p>
            </div>
        </div>
        <div class="header-actions">
            <button id="btn-start-db-scan" class="wps-btn wps-btn-accent">
                <span class="dashicons dashicons-search"></span> <?php esc_html_e('Scan Database Now', 'wp-shieldx'); ?>
            </button>
        </div>
    </div>

    <!-- Scan Progress / Status Box -->
    <div id="db-scan-status-box" class="wps-card" style="display: none;">
        <span class="dashicons dashicons-update spin"></span>
        <strong id="db-scan-status-text"><?php esc_html_e('Scanning database tables...', 'wp-shieldx'); ?></strong>
    </div>

    <!-- Findings Table Container -->
    <div class="wps-card">
        <div class="card-head">
            <h3>&#9888; <?php esc_html_e('Database Injection Findings', 'wp-shieldx'); ?> <span id="db-threat-count" class="badge badge-threat">0</span></h3>
        </div>

        <div id="db-empty-state" class="empty-state">
            <div class="empty-icon text-success">&#10004;</div>
            <h3><?php esc_html_e('Database Scan Ready', 'wp-shieldx'); ?></h3>
            <p><?php esc_html_e('Click "Scan Database Now" to inspect your posts, site options, and comments for hidden malicious code.', 'wp-shieldx'); ?></p>
        </div>

        <table id="db-findings-table" class="wps-table" style="display: none;">
            <thead>
                <tr>
                    <th><?php esc_html_e('Severity', 'wp-shieldx'); ?></th>
                    <th><?php esc_html_e('Threat Classification', 'wp-shieldx'); ?></th>
                    <th style="width: 25%;"><?php esc_html_e('Location & Record', 'wp-shieldx'); ?></th>
                    <th style="width: 35%;"><?php esc_html_e('Injected Payload Snippet', 'wp-shieldx'); ?></th>
                    <th style="text-align: right;"><?php esc_html_e('Action', 'wp-shieldx'); ?></th>
                </tr>
            </thead>
            <tbody id="db-findings-body">
            </tbody>
        </table>
    </div>
</div>
