<?php
/**
 * WP ShieldX 1-Click System Hardening Engine
 * Enforces core hardening toggles: file editing disable, version hiding, directory listing blocks, and config shields.
 */

if (!defined('ABSPATH')) {
    exit;
}

class WP_ShieldX_Hardening {

    /**
     * Initialize active hardening policies
     */
    public static function init() {
        $settings = get_option('wp_shieldx_settings', []);

        // 1. Disable Theme & Plugin File Editor in WP Admin
        if (!empty($settings['harden_disable_file_edit'])) {
            if (!defined('DISALLOW_FILE_EDIT')) {
                define('DISALLOW_FILE_EDIT', true);
            }
            add_filter('map_meta_cap', [__CLASS__, 'filter_file_edit_capabilities'], 10, 4);
        }

        // 2. Hide WordPress Version Meta & Asset Fingerprints
        if (!empty($settings['harden_hide_wp_version'])) {
            remove_action('wp_head', 'wp_generator');
            add_filter('the_generator', '__return_empty_string');
            add_filter('style_loader_src', [__CLASS__, 'remove_asset_version_string'], 9999);
            add_filter('script_loader_src', [__CLASS__, 'remove_asset_version_string'], 9999);
        }

        // 3. Disable Application Passwords
        if (!empty($settings['harden_disable_app_passwords'])) {
            add_filter('wp_is_application_passwords_available', '__return_false');
        }

        // 4. Ensure .htaccess hardening rules are synced
        self::sync_htaccess_rules($settings);
    }

    /**
     * Prevent theme/plugin editing via capability filter
     */
    public static function filter_file_edit_capabilities($caps, $cap, $user_id, $args) {
        if (in_array($cap, ['edit_plugins', 'edit_themes'], true)) {
            $caps[] = 'do_not_allow';
        }
        return $caps;
    }

    /**
     * Remove ?ver= query string from frontend asset URLs
     */
    public static function remove_asset_version_string($src) {
        if (is_admin()) {
            return $src;
        }
        if (strpos($src, 'ver=')) {
            $src = remove_query_arg('ver', $src);
        }
        return $src;
    }

    /**
     * Sync .htaccess hardening rules in WordPress root
     */
    public static function sync_htaccess_rules($settings) {
        // Run once per day or upon saving settings
        if (defined('DOING_CRON') && DOING_CRON) {
            return;
        }

        $htaccess_file = wp_normalize_path(ABSPATH . '.htaccess');
        if (!file_exists($htaccess_file) || !is_writable($htaccess_file)) {
            return;
        }

        $content = @file_get_contents($htaccess_file);
        if ($content === false) {
            return;
        }

        $start_marker = '# BEGIN WP ShieldX Hardening';
        $end_marker   = '# END WP ShieldX Hardening';

        $rules = [];
        if (!empty($settings['harden_disable_directory_browsing'])) {
            $rules[] = "Options -Indexes";
        }
        if (!empty($settings['harden_protect_wp_config'])) {
            $rules[] = "<Files wp-config.php>\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order Deny,Allow\n    Deny from all\n</IfModule>\n</Files>";
        }

        $block = "";
        if (!empty($rules)) {
            $block = $start_marker . "\n" . implode("\n", $rules) . "\n" . $end_marker . "\n";
        }

        // Replace or append
        if (strpos($content, $start_marker) !== false) {
            $pattern = '/' . preg_quote($start_marker, '/') . '.*?' . preg_quote($end_marker, '/') . '\s*/s';
            $content = preg_replace($pattern, $block, $content);
        } else {
            if (!empty($block)) {
                $content = $block . "\n" . $content;
            }
        }

        @file_put_contents($htaccess_file, $content);
    }
}
