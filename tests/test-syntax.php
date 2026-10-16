<?php
/**
 * WP ShieldX Syntax & Integrity Verification Test Script
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', dirname(__DIR__) . '/');
}

echo "===> Testing WP ShieldX Plugin Syntax & Class Structures...\n";

$files = [
    __DIR__ . '/../wp-shieldx.php',
    __DIR__ . '/../wp-secure.php',
    __DIR__ . '/../uninstall.php',
    __DIR__ . '/../includes/class-wp-shieldx-database.php',
    __DIR__ . '/../includes/class-wp-shieldx-signatures.php',
    __DIR__ . '/../includes/class-wp-shieldx-notifier.php',
    __DIR__ . '/../includes/class-wp-shieldx-repair.php',
    __DIR__ . '/../includes/class-wp-shieldx-file-monitor.php',
    __DIR__ . '/../includes/class-wp-shieldx-malware-scanner.php',
    __DIR__ . '/../includes/class-wp-shieldx-db-scanner.php',
    __DIR__ . '/../includes/class-wp-shieldx-vulnerability-auditor.php',
    __DIR__ . '/../includes/class-wp-shieldx-hardening.php',
    __DIR__ . '/../includes/class-wp-shieldx-backup.php',
    __DIR__ . '/../includes/class-wp-shieldx-firewall.php',
    __DIR__ . '/../includes/class-wp-shieldx-activator.php',
    __DIR__ . '/../includes/class-wp-shieldx-deactivator.php',
    __DIR__ . '/../includes/class-wp-shieldx-core.php',
    __DIR__ . '/../admin/class-wp-shieldx-admin.php',
];

$all_passed = true;

foreach ($files as $file) {
    $real = realpath($file);
    if (!$real || !file_exists($real)) {
        echo "[FAIL] File missing: $file\n";
        $all_passed = false;
        continue;
    }

    $cmd = 'php -l ' . escapeshellarg($real);
    exec($cmd, $output, $return_var);

    if ($return_var === 0) {
        echo "[PASS] " . basename($real) . "\n";
    } else {
        echo "[ERROR] Syntax error in " . basename($real) . ":\n" . implode("\n", $output) . "\n";
        $all_passed = false;
    }
    $output = [];
}

// Test Signature Regexes to ensure they compile without errors
require_once __DIR__ . '/../includes/class-wp-shieldx-signatures.php';
$patterns = WP_ShieldX_Signatures::get_patterns();
echo "===> Testing " . count($patterns) . " Threat Signature Regex Patterns...\n";

foreach ($patterns as $p) {
    if (@preg_match($p['pattern'], '') === false) {
        echo "[ERROR] Invalid regex in pattern: " . $p['id'] . "\n";
        $all_passed = false;
    } else {
        echo "[PASS] Pattern compiled: " . $p['id'] . " (" . $p['name'] . ")\n";
    }
}

// Test Shannon Entropy Calculator
$sample_repetitive = base64_encode(str_repeat("AAAAABBBBBCCCCCDDDDD", 5));
$sample_encrypted_base64 = base64_encode(random_bytes(64));
$e_rep = WP_ShieldX_Signatures::calculate_entropy($sample_repetitive);
$e_enc = WP_ShieldX_Signatures::calculate_entropy($sample_encrypted_base64);
echo sprintf("===> Entropy Test: Repetitive Base64 = %.2f, Encrypted Random Base64 = %.2f\n", $e_rep, $e_enc);

if ($e_enc > $e_rep && $e_enc > 5.0) {
    echo "[PASS] Entropy calculation properly discriminates high-density obfuscated text.\n";
} else {
    echo "[ERROR] Entropy calculation failed discrimination.\n";
    $all_passed = false;
}

if ($all_passed) {
    echo "\n>>> ALL WP SHIELDX TESTS PASSED WITH 0 ERRORS! <<<\n";
    exit(0);
} else {
    echo "\n>>> FAILURES DETECTED! <<<\n";
    exit(1);
}
