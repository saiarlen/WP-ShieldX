<?php
/**
 * WP ShieldX Plugin Deactivator
 */

if (!defined('ABSPATH')) {
    exit;
}

class WP_ShieldX_Deactivator {

    public static function deactivate() {
        // Clear scheduled cron events
        $timestamp = wp_next_scheduled('wp_shieldx_scheduled_scan');
        if ($timestamp) {
            wp_unschedule_event($timestamp, 'wp_shieldx_scheduled_scan');
        }
    }
}
