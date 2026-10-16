<?php
if (!defined('ABSPATH')) {
    exit;
}

$settings = get_option('wp_shieldx_settings', [
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
]);
?>

<div class="wrap wp-shieldx-wrap">
    <div class="wp-shieldx-header">
        <div class="wp-shieldx-brand">
            <span class="brand-icon">&#9881;</span>
            <div>
                <h1><?php esc_html_e('WP ShieldX Security Settings', 'wp-shieldx'); ?></h1>
                <p><?php esc_html_e('Configure firewall sensitivity, email attack notifications, IP allowlists, and scan automation.', 'wp-shieldx'); ?></p>
            </div>
        </div>
    </div>

    <form id="wps-settings-form" class="wps-form">
        <!-- Notification Settings -->
        <div class="wps-card">
            <div class="card-head">
                <h3>&#9993; <?php esc_html_e('Email Attack Alerts & Notifications', 'wp-shieldx'); ?></h3>
            </div>
            <div class="form-group">
                <label for="alert_email"><strong><?php esc_html_e('Alert Recipient Email:', 'wp-shieldx'); ?></strong></label>
                <input type="email" id="alert_email" name="alert_email" class="wps-input" value="<?php echo esc_attr(!empty($settings['alert_email']) ? $settings['alert_email'] : get_option('admin_email')); ?>" style="max-width: 400px;" required>
                <p class="description"><?php esc_html_e('Instant security alerts and remediation reports will be dispatched to this address.', 'wp-shieldx'); ?></p>
            </div>

            <div class="form-group">
                <label>
                    <input type="checkbox" name="email_notifications" value="1" <?php checked(!empty($settings['email_notifications'])); ?>>
                    <strong><?php esc_html_e('Enable Automated Security Email Alerts', 'wp-shieldx'); ?></strong>
                </label>
            </div>

            <div class="form-indent">
                <label class="checkbox-row">
                    <input type="checkbox" name="notify_on_firewall" value="1" <?php checked(!empty($settings['notify_on_firewall'])); ?>>
                    <span><?php esc_html_e('Notify on high-severity Firewall attack blocks (SQLi, XSS, RFI, brute force lockouts)', 'wp-shieldx'); ?></span>
                </label>
                <label class="checkbox-row">
                    <input type="checkbox" name="notify_on_file_change" value="1" <?php checked(!empty($settings['notify_on_file_change'])); ?>>
                    <span><?php esc_html_e('Notify when files are added, modified, or deleted unexpectedly', 'wp-shieldx'); ?></span>
                </label>
                <label class="checkbox-row">
                    <input type="checkbox" name="notify_on_malware" value="1" <?php checked(!empty($settings['notify_on_malware'])); ?>>
                    <span><?php esc_html_e('Notify immediately when malware, webshells, or core checksum discrepancies are detected', 'wp-shieldx'); ?></span>
                </label>
            </div>
        </div>

        <!-- Firewall Settings -->
        <div class="wps-card">
            <div class="card-head">
                <h3>&#128737; <?php esc_html_e('Web Application Firewall (WAF) & Hardening', 'wp-shieldx'); ?></h3>
            </div>
            <div class="form-group">
                <label>
                    <input type="checkbox" name="waf_enabled" value="1" <?php checked(!empty($settings['waf_enabled'])); ?>>
                    <strong><?php esc_html_e('Enable Active Firewall Request Inspection (WAF)', 'wp-shieldx'); ?></strong>
                </label>
                <p class="description"><?php esc_html_e('Inspects all incoming GET, POST, COOKIE, and URI variables against threat signatures.', 'wp-shieldx'); ?></p>
            </div>

            <div class="form-group">
                <label>
                    <input type="checkbox" name="disable_xmlrpc" value="1" <?php checked(!empty($settings['disable_xmlrpc'])); ?>>
                    <strong><?php esc_html_e('Disable XML-RPC Endpoint', 'wp-shieldx'); ?></strong>
                </label>
                <p class="description"><?php esc_html_e('Shields against XML-RPC brute force attacks and DDoS amplification.', 'wp-shieldx'); ?></p>
            </div>
        </div>

        <!-- IP Access Lists -->
        <div class="wps-grid-2">
            <div class="wps-card">
                <div class="card-head">
                    <h3>&#10004; <?php esc_html_e('IP Whitelist (Trusted)', 'wp-shieldx'); ?></h3>
                </div>
                <div class="form-group">
                    <textarea name="ip_whitelist" class="wps-textarea" rows="5" placeholder="127.0.0.1&#10;192.168.1.100"><?php echo esc_textarea(isset($settings['ip_whitelist']) ? $settings['ip_whitelist'] : ''); ?></textarea>
                    <p class="description"><?php esc_html_e('One IP per line. Requests from these IPs bypass firewall blocks.', 'wp-shieldx'); ?></p>
                </div>
            </div>

            <div class="wps-card">
                <div class="card-head">
                    <h3>&#10008; <?php esc_html_e('IP Blacklist (Blocked)', 'wp-shieldx'); ?></h3>
                </div>
                <div class="form-group">
                    <textarea name="ip_blacklist" class="wps-textarea" rows="5" placeholder="203.0.113.1&#10;198.51.100.5"><?php echo esc_textarea(isset($settings['ip_blacklist']) ? $settings['ip_blacklist'] : ''); ?></textarea>
                    <p class="description"><?php esc_html_e('One IP per line. Requests from these IPs are permanently rejected with 403 Forbidden.', 'wp-shieldx'); ?></p>
                </div>
            </div>
        </div>

        <div style="margin-top: 20px;">
            <button type="submit" id="btn-save-settings" class="wps-btn wps-btn-primary">
                <span class="dashicons dashicons-saved"></span> <?php esc_html_e('Save Security Configurations', 'wp-shieldx'); ?>
            </button>
            <span id="save-status" style="margin-left: 12px; font-weight: 600;"></span>
        </div>
    </form>
</div>
