<?php
/**
 * WP ShieldX Alert & Email Notification Engine
 * Dispatches responsive HTML alert emails for blocked attacks, malware findings, and file modifications.
 */

if (!defined('ABSPATH')) {
    exit;
}

class WP_ShieldX_Notifier {

    /**
     * Send security incident email alert
     *
     * @param string $event_type 'FIREWALL_ATTACK', 'FILE_MODIFIED', 'NEW_FILE', 'FILE_DELETED', 'MALWARE_DETECTED'
     * @param string $subject
     * @param array $details Key-value pairs for incident info
     * @param string $severity 'critical', 'high', 'medium', 'low'
     * @return bool
     */
    public static function notify($event_type, $subject, $details = [], $severity = 'high') {
        $options = get_option('wp_shieldx_settings', []);
        $enabled = isset($options['email_notifications']) ? (bool)$options['email_notifications'] : true;
        
        if (!$enabled) {
            return false;
        }

        // Check specific event type toggles
        if ($event_type === 'FIREWALL_ATTACK' && empty($options['notify_on_firewall'])) {
            return false;
        }
        if (in_array($event_type, ['FILE_MODIFIED', 'NEW_FILE', 'FILE_DELETED'], true) && empty($options['notify_on_file_change'])) {
            return false;
        }
        if ($event_type === 'MALWARE_DETECTED' && empty($options['notify_on_malware'])) {
            return false;
        }

        // Flood protection: do not send more than 1 notification per 3 minutes for identical event types
        $transient_key = 'wp_shieldx_alert_' . md5($event_type . serialize($details));
        if (get_transient($transient_key)) {
            return false;
        }
        set_transient($transient_key, 1, 180);

        $recipient = !empty($options['alert_email']) ? sanitize_email($options['alert_email']) : get_option('admin_email');
        if (!is_email($recipient)) {
            return false;
        }

        $site_name = get_bloginfo('name');
        $site_url  = get_site_url();
        $admin_url = admin_url('admin.php?page=wp-shieldx');

        $full_subject = sprintf('[%s Security Alert] [%s] %s', strtoupper($severity), $site_name, $subject);

        // Build HTML Body
        $severity_color = '#e53e3e'; // red
        if ($severity === 'medium') {
            $severity_color = '#dd6b20'; // orange
        } elseif ($severity === 'low') {
            $severity_color = '#3182ce'; // blue
        }

        ob_start();
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #334155; margin: 0; padding: 20px; }
                .email-card { max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
                .email-header { background: #1e293b; padding: 24px; color: #ffffff; text-align: left; border-bottom: 4px solid <?php echo esc_attr($severity_color); ?>; }
                .email-header h1 { margin: 0; font-size: 20px; font-weight: 700; color: #f8fafc; }
                .badge { display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 11px; font-weight: 700; text-transform: uppercase; background: <?php echo esc_attr($severity_color); ?>; color: #ffffff; margin-top: 8px; }
                .email-body { padding: 24px; }
                .intro { font-size: 15px; line-height: 1.5; color: #334155; margin-bottom: 20px; }
                .details-table { width: 100%; border-collapse: collapse; margin-bottom: 24px; }
                .details-table td { padding: 10px 12px; font-size: 13px; border-bottom: 1px solid #e2e8f0; }
                .details-table td.label { font-weight: 600; width: 35%; color: #64748b; background-color: #f8fafc; }
                .details-table td.value { color: #0f172a; word-break: break-all; }
                .btn { display: inline-block; background-color: #0284c7; color: #ffffff !important; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-weight: 600; font-size: 14px; text-align: center; }
                .email-footer { background: #f8fafc; padding: 16px 24px; font-size: 12px; color: #94a3b8; text-align: center; border-top: 1px solid #e2e8f0; }
            </style>
        </head>
        <body>
            <div class="email-card">
                <div class="email-header">
                    <h1>&#128737; WP ShieldX Security Notice</h1>
                    <div class="badge"><?php echo esc_html(strtoupper($severity)); ?> ALERT</div>
                </div>
                <div class="email-body">
                    <p class="intro">WP ShieldX detected an urgent security event on your site <strong><?php echo esc_html($site_name); ?></strong> (<?php echo esc_html($site_url); ?>):</p>
                    <table class="details-table">
                        <tr>
                            <td class="label">Event Type</td>
                            <td class="value"><strong><?php echo esc_html(str_replace('_', ' ', $event_type)); ?></strong></td>
                        </tr>
                        <tr>
                            <td class="label">Timestamp</td>
                            <td class="value"><?php echo esc_html(current_time('mysql')); ?> (Server Time)</td>
                        </tr>
                        <?php foreach ($details as $key => $val): ?>
                            <tr>
                                <td class="label"><?php echo esc_html(ucwords(str_replace('_', ' ', $key))); ?></td>
                                <td class="value"><?php echo esc_html($val); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </table>
                    <div style="text-align: center; margin: 30px 0 10px;">
                        <a href="<?php echo esc_url($admin_url); ?>" class="btn">Open WP ShieldX Dashboard &rarr;</a>
                    </div>
                </div>
                <div class="email-footer">
                    Sent automatically by WP ShieldX on <?php echo esc_html($site_url); ?>.<br>
                    Keep your WordPress installation hardened and monitor changes frequently.
                </div>
            </div>
        </body>
        </html>
        <?php
        $body = ob_get_clean();

        $headers = [
            'Content-Type: text/html; charset=UTF-8',
            'From: ' . $site_name . ' Security <' . get_option('admin_email') . '>'
        ];

        return wp_mail($recipient, $full_subject, $body, $headers);
    }
}
