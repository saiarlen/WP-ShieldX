<?php
/**
 * WP ShieldX Threat Signatures & Heuristics
 * Contains high-precision signatures and patterns for malware, webshells, and weird patterns.
 */

if (!defined('ABSPATH')) {
    exit;
}

class WP_ShieldX_Signatures {

    /**
     * Get malware & backdoor pattern definitions
     *
     * @return array
     */
    public static function get_patterns() {
        return [
            // 1. Obfuscated Eval & Execution Backdoors
            [
                'id'          => 'OBFUSCATED_EVAL_BASE64',
                'name'        => 'Obfuscated Base64 Eval Backdoor',
                'severity'    => 'critical',
                'type'        => 'OBFUSCATION',
                'pattern'     => '/eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|pack)\s*\(/i',
                'description' => 'Evaluates decoded/decompressed payload dynamically in memory.'
            ],
            [
                'id'          => 'PREG_REPLACE_EVAL',
                'name'        => 'Deprecated preg_replace /e Code Execution',
                'severity'    => 'critical',
                'type'        => 'RCE',
                'pattern'     => '/preg_replace\s*\(\s*([\'"])(?:(?!\1).)*\/[a-z]*e[a-z]*\1\s*,/i',
                'description' => 'Code execution via deprecated /e regex modifier.'
            ],
            [
                'id'          => 'CREATE_FUNCTION_BACKDOOR',
                'name'        => 'create_function() Anonymous Execution',
                'severity'    => 'high',
                'type'        => 'RCE',
                'pattern'     => '/create_function\s*\(\s*[\'"][^\'"]*[\'"]\s*,\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|base64_decode|str_rot13)/i',
                'description' => 'Anonymous code execution via create_function wrapper.'
            ],
            [
                'id'          => 'DIRECT_REQUEST_SHELL_EXEC',
                'name'        => 'Direct User Input to Shell Command',
                'severity'    => 'critical',
                'type'        => 'WEBSHELL',
                'pattern'     => '/\b(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[/i',
                'description' => 'Direct invocation of system shell with untrusted HTTP request parameters.'
            ],
            [
                'id'          => 'ASSERT_DYNAMIC_EXECUTION',
                'name'        => 'assert() Dynamic Code Evaluation',
                'severity'    => 'critical',
                'type'        => 'WEBSHELL',
                'pattern'     => '/assert\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|base64_decode|file_get_contents)\s*\[?/i',
                'description' => 'Arbitrary PHP execution via assert() construct.'
            ],
            [
                'id'          => 'CHR_CONCATENATION_OBFUSCATION',
                'name'        => 'Long Chained chr() Obfuscation',
                'severity'    => 'medium',
                'type'        => 'OBFUSCATION',
                'pattern'     => '/(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){6,}/i',
                'description' => 'Long chain of character byte assembly typically used to conceal strings.'
            ],
            [
                'id'          => 'VARIABLE_FUNCTION_INJECTION',
                'name'        => 'Variable Function Call with Superglobal',
                'severity'    => 'critical',
                'type'        => 'WEBSHELL',
                'pattern'     => '/\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[[^\]]+\]\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)/i',
                'description' => 'Dynamic variable function dispatch utilizing external request variables.'
            ],

            // 2. Known Webshell Identifiers
            [
                'id'          => 'KNOWN_WEBSHELL_STRINGS',
                'name'        => 'Known Webshell Identifier Signature',
                'severity'    => 'critical',
                'type'        => 'WEBSHELL',
                'pattern'     => '/\b(?:c99shell|r57shell|WSO_VERSION|b374k|FilesMan|Alfa\s+Team|IndoXploit|Mini\s+Shell|weevely|ALFA_DATA|phpspy|Ani-Shell|SimAttacker)\b/i',
                'description' => 'Matches signature headers and names of widespread PHP webshells.'
            ],
            [
                'id'          => 'WSO_AUTH_HASH',
                'name'        => 'WSO Webshell Authentication Hash',
                'severity'    => 'critical',
                'type'        => 'WEBSHELL',
                'pattern'     => '/\$auth_pass\s*=\s*[\'"][0-9a-f]{32}[\'"]/i',
                'description' => 'Classic password hash assignment typical in WSO / FilesMan webshells.'
            ],

            // 3. Rogue WordPress Account Creation
            [
                'id'          => 'ROGUE_ADMIN_CREATOR',
                'name'        => 'Suspicious Silent Admin User Creation',
                'severity'    => 'critical',
                'type'        => 'PRIVILEGE_ESCALATION',
                'pattern'     => '/wp_create_user\s*\([^\)]*\);\s*\$user\s*->\s*set_role\s*\(\s*[\'"]administrator[\'"]\s*\)/i',
                'description' => 'Silent insertion of an administrator account.'
            ],

            // 4. Stealth Headers & Error Hiding
            [
                'id'          => 'ERROR_SILENCER_WITH_EXEC',
                'name'        => 'Stealth Execution with Suppressed Errors',
                'severity'    => 'high',
                'type'        => 'STEALTH',
                'pattern'     => '/@ini_set\s*\(\s*[\'"]display_errors[\'"]\s*,\s*0\s*\);.*?(?:eval|assert|system|exec|passthru)/is',
                'description' => 'Concealing PHP error messages while executing dynamic instructions.'
            ],

            // 5. Malicious Hex Chains
            [
                'id'          => 'HEX_ENCODED_EVAL',
                'name'        => 'Hex Escaped Eval Construct',
                'severity'    => 'critical',
                'type'        => 'OBFUSCATION',
                'pattern'     => '/\\\x65\\\x76\\\x61\\\x6c/i', // \x65\x76\x61\x6c = eval
                'description' => 'Hexadecimal-escaped eval statement.'
            ],
            [
                'id'          => 'HEX_ENCODED_ASSERT',
                'name'        => 'Hex Escaped Assert Construct',
                'severity'    => 'critical',
                'type'        => 'OBFUSCATION',
                'pattern'     => '/\\\x61\\\x73\\\x73\\\x65\\\x72\\\x74/i', // \x61\x73\x73\x65\x72\x74 = assert
                'description' => 'Hexadecimal-escaped assert statement.'
            ]
        ];
    }

    /**
     * Calculate Shannon Entropy of a string to detect encrypted/packed content
     *
     * @param string $data
     * @return float
     */
    public static function calculate_entropy($data) {
        $len = strlen($data);
        if ($len === 0) {
            return 0.0;
        }

        $frequencies = count_chars($data, 1);
        $entropy = 0.0;

        foreach ($frequencies as $count) {
            $p = $count / $len;
            $entropy -= $p * log($p, 2);
        }

        return $entropy;
    }

    /**
     * Check if a file extension is executable
     *
     * @param string $path
     * @return bool
     */
    public static function is_executable_extension($path) {
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        return in_array($ext, ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'inc'], true);
    }
}
