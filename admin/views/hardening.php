<?php
if (!defined('ABSPATH')) {
    exit;
}

$settings = get_option('wp_shieldx_settings', []);
?>

<div class="wrap wp-shieldx-wrap">
    <div class="wp-shieldx-header">
        <div class="wp-shieldx-brand">
            <span class="brand-icon">&#128274;</span>
            <div>
                <h1><?php esc_html_e('1-Click System Hardening Policies', 'wp-shieldx'); ?></h1>
                <p><?php esc_html_e('Enforce proactive security restrictions that shut down attack vectors before hackers can exploit them.', 'wp-shieldx'); ?></p>
            </div>
        </div>
    </div>

    <form id="wps-hardening-form">
        <div class="wps-grid-2">
            <!-- File Editor Shield -->
            <div class="wps-card wps-shield-card">
                <div class="shield-title">&#9997; <?php esc_html_e('Disable File Editing in WP Admin', 'wp-shieldx'); ?></div>
                <p><?php esc_html_e('Disables the built-in theme and plugin file editor. Even if an attacker compromises an administrator password, they cannot inject code via the admin dashboard.', 'wp-shieldx'); ?></p>
                <label class="checkbox-row" style="margin-top: 14px;">
                    <input type="checkbox" name="harden_disable_file_edit" value="1" <?php checked(!empty($settings['harden_disable_file_edit'])); ?>>
                    <strong><?php esc_html_e('Enforce DISALLOW_FILE_EDIT', 'wp-shieldx'); ?></strong>
                </label>
            </div>

            <!-- Hide WP Version -->
            <div class="wps-card wps-shield-card">
                <div class="shield-title">&#128065; <?php esc_html_e('Hide WordPress Version Meta & Fingerprints', 'wp-shieldx'); ?></div>
                <p><?php esc_html_e('Removes the generator meta tag from HTML source and strips version query strings (?ver=...) from CSS/JS assets, hiding known-version exploits from automated scanners.', 'wp-shieldx'); ?></p>
                <label class="checkbox-row" style="margin-top: 14px;">
                    <input type="checkbox" name="harden_hide_wp_version" value="1" <?php checked(!empty($settings['harden_hide_wp_version'])); ?>>
                    <strong><?php esc_html_e('Conceal WordPress Version', 'wp-shieldx'); ?></strong>
                </label>
            </div>

            <!-- Disable Directory Browsing -->
            <div class="wps-card wps-shield-card">
                <div class="shield-title">&#128193; <?php esc_html_e('Disable Directory Browsing (Indexes)', 'wp-shieldx'); ?></div>
                <p><?php esc_html_e('Injects Options -Indexes into .htaccess to prevent visitors and reconnaissance bots from listing files in folders without index.php.', 'wp-shieldx'); ?></p>
                <label class="checkbox-row" style="margin-top: 14px;">
                    <input type="checkbox" name="harden_disable_directory_browsing" value="1" <?php checked(!empty($settings['harden_disable_directory_browsing'])); ?>>
                    <strong><?php esc_html_e('Block Directory Indexing', 'wp-shieldx'); ?></strong>
                </label>
            </div>

            <!-- Disable Application Passwords -->
            <div class="wps-card wps-shield-card">
                <div class="shield-title">&#128272; <?php esc_html_e('Disable Application Passwords', 'wp-shieldx'); ?></div>
                <p><?php esc_html_e('Disables WordPress Application Passwords for the REST API if your site does not require external app integrations, preventing rogue API key creation.', 'wp-shieldx'); ?></p>
                <label class="checkbox-row" style="margin-top: 14px;">
                    <input type="checkbox" name="harden_disable_app_passwords" value="1" <?php checked(!empty($settings['harden_disable_app_passwords'])); ?>>
                    <strong><?php esc_html_e('Disable Application Passwords', 'wp-shieldx'); ?></strong>
                </label>
            </div>

            <!-- Protect wp-config.php -->
            <div class="wps-card wps-shield-card" style="grid-column: span 2;">
                <div class="shield-title">&#128737; <?php esc_html_e('Shield wp-config.php via Web Server Rules', 'wp-shieldx'); ?></div>
                <p><?php esc_html_e('Prevents direct HTTP/HTTPS web requests targeting wp-config.php and database configuration backups via server directives.', 'wp-shieldx'); ?></p>
                <label class="checkbox-row" style="margin-top: 14px;">
                    <input type="checkbox" name="harden_protect_wp_config" value="1" <?php checked(!empty($settings['harden_protect_wp_config'])); ?>>
                    <strong><?php esc_html_e('Block Direct Access to wp-config.php', 'wp-shieldx'); ?></strong>
                </label>
            </div>
        </div>

        <div style="margin-top: 10px;">
            <button type="submit" id="btn-save-hardening" class="wps-btn wps-btn-primary">
                <span class="dashicons dashicons-shield"></span> <?php esc_html_e('Apply Hardening Policies', 'wp-shieldx'); ?>
            </button>
            <span id="harden-status" style="margin-left: 12px; font-weight: 600;"></span>
        </div>
    </form>
</div>
