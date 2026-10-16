<?php
/**
 * Plugin Name:       WP ShieldX - Advanced Security, File Monitor & Firewall
 * Plugin URI:        https://github.com/saiarlen/wp-shieldx
 * Description:       Next-generation WordPress cybersecurity suite: Real-time File Integrity Monitor (added/modified/deleted files), Deep Malware & Weird Pattern Heuristic Scanner with WordPress.org Core Checksums API, Active Request Firewall (WAF), Database Threat & SEO Spam Scanner, 1-Click System Hardening, Pre-Update Rollback Snapshots, and One-Click File Quarantine & Core Repair.
 * Version:           1.0.0
 * Author:            saiarlen
 * Author URI:        https://www.saiarlen.com
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       wp-shieldx
 * Domain Path:       /languages
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

define('WP_SHIELDX_VERSION', '1.0.0');
define('WP_SHIELDX_PLUGIN_FILE', __FILE__);
define('WP_SHIELDX_PATH', plugin_dir_path(__FILE__));
define('WP_SHIELDX_URL', plugin_dir_url(__FILE__));
define('WP_SHIELDX_BASENAME', plugin_basename(__FILE__));

// Autoload plugin dependencies & classes
require_once WP_SHIELDX_PATH . 'includes/class-wp-shieldx-database.php';
require_once WP_SHIELDX_PATH . 'includes/class-wp-shieldx-signatures.php';
require_once WP_SHIELDX_PATH . 'includes/class-wp-shieldx-notifier.php';
require_once WP_SHIELDX_PATH . 'includes/class-wp-shieldx-repair.php';
require_once WP_SHIELDX_PATH . 'includes/class-wp-shieldx-file-monitor.php';
require_once WP_SHIELDX_PATH . 'includes/class-wp-shieldx-malware-scanner.php';
require_once WP_SHIELDX_PATH . 'includes/class-wp-shieldx-db-scanner.php';
require_once WP_SHIELDX_PATH . 'includes/class-wp-shieldx-vulnerability-auditor.php';
require_once WP_SHIELDX_PATH . 'includes/class-wp-shieldx-hardening.php';
require_once WP_SHIELDX_PATH . 'includes/class-wp-shieldx-backup.php';
require_once WP_SHIELDX_PATH . 'includes/class-wp-shieldx-firewall.php';
require_once WP_SHIELDX_PATH . 'includes/class-wp-shieldx-activator.php';
require_once WP_SHIELDX_PATH . 'includes/class-wp-shieldx-deactivator.php';
require_once WP_SHIELDX_PATH . 'admin/class-wp-shieldx-admin.php';
require_once WP_SHIELDX_PATH . 'includes/class-wp-shieldx-core.php';

/**
 * Register activation & deactivation hooks
 */
register_activation_hook(__FILE__, ['WP_ShieldX_Activator', 'activate']);
register_deactivation_hook(__FILE__, ['WP_ShieldX_Deactivator', 'deactivate']);

/**
 * Run WP ShieldX Core
 */
function wp_shieldx_init() {
    $plugin = WP_ShieldX_Core::get_instance();
    $plugin->run();
}
add_action('plugins_loaded', 'wp_shieldx_init');
