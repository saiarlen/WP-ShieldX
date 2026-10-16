<?php
/**
 * WP ShieldX Database Threat & SEO Spam Scanner
 * Scans wp_posts, wp_options, and wp_comments for malicious scripts, hidden iframes, and SEO redirects.
 */

if (!defined('ABSPATH')) {
    exit;
}

class WP_ShieldX_DB_Scanner {

    /**
     * Threat patterns for database scanning
     */
    public static function get_db_patterns() {
        return [
            [
                'id'          => 'MALICIOUS_SCRIPT_TAG',
                'name'        => 'Remote Script Injection Tag',
                'severity'    => 'critical',
                'pattern'     => '/<script\b[^>]*src=[\'"]https?:\/\/(?!(?:www\.)?(?:google|gstatic|googleapis|cloudflare|jquery|wordpress|jsdelivr)\.com)[^\'"]+[\'"][^>]*>.*?<\/script>/i',
                'description' => 'Unverified external JavaScript library or payload injected into database content.'
            ],
            [
                'id'          => 'HIDDEN_IFRAME_INJECTION',
                'name'        => 'Hidden Malicious Iframe',
                'severity'    => 'critical',
                'pattern'     => '/<iframe\b[^>]*(?:display:\s*none|visibility:\s*hidden|width:\s*0|height:\s*0|opacity:\s*0)[^>]*>.*?<\/iframe>/i',
                'description' => 'Zero-dimension or hidden iframe used for clickjacking or drive-by downloads.'
            ],
            [
                'id'          => 'BASE64_DATA_PAYLOAD',
                'name'        => 'Base64 Executable Script URI',
                'severity'    => 'high',
                'pattern'     => '/data:text\/(?:javascript|html);base64,[a-zA-Z0-9+\/]{40,}={0,2}/i',
                'description' => 'Base64 data URI concealing inline executable JavaScript.'
            ],
            [
                'id'          => 'MALICIOUS_REDIRECT_JS',
                'name'        => 'SEO Spam / Rogue Redirection Script',
                'severity'    => 'critical',
                'pattern'     => '/(?:window\.location(?:\.href)?|document\.location)\s*=\s*[\'"]https?:\/\/[^\'"]+[\'"]/i',
                'description' => 'Forced browser redirection script injected into database post content.'
            ],
            [
                'id'          => 'PHP_CODE_IN_CONTENT',
                'name'        => 'Raw PHP Opening Tag In Content',
                'severity'    => 'high',
                'pattern'     => '/<\?(?:php|=)\s+(?:eval|assert|system|passthru|shell_exec|base64_decode)/i',
                'description' => 'PHP code execution payload placed inside posts or options.'
            ]
        ];
    }

    /**
     * Run full database threat scan across posts, options, and comments
     *
     * @return array Findings
     */
    public static function scan_database() {
        global $wpdb;
        $findings = [];
        $patterns = self::get_db_patterns();

        // 1. Scan Posts Table
        $posts = $wpdb->get_results("SELECT ID, post_title, post_content, post_type FROM {$wpdb->posts} WHERE post_status IN ('publish', 'draft', 'pending') AND post_content != '' LIMIT 1000");
        foreach ($posts as $post) {
            foreach ($patterns as $p) {
                if (preg_match($p['pattern'], $post->post_content, $matches)) {
                    $snippet = substr($matches[0], 0, 160);
                    $findings[] = [
                        'table'       => 'posts',
                        'record_id'   => $post->ID,
                        'record_title'=> $post->post_title ? $post->post_title : ('Post #' . $post->ID),
                        'field'       => 'post_content',
                        'threat_id'   => $p['id'],
                        'threat_name' => $p['name'],
                        'severity'    => $p['severity'],
                        'snippet'     => $snippet
                    ];
                }
            }
        }

        // 2. Scan Options Table (Common siteurl/home takeover, rogue widgets, headers)
        $options = $wpdb->get_results("SELECT option_id, option_name, option_value FROM {$wpdb->options} WHERE option_name NOT LIKE '%_transient_%' AND LENGTH(option_value) > 20 LIMIT 600");
        foreach ($options as $opt) {
            foreach ($patterns as $p) {
                if (preg_match($p['pattern'], $opt->option_value, $matches)) {
                    $snippet = substr($matches[0], 0, 160);
                    $findings[] = [
                        'table'       => 'options',
                        'record_id'   => $opt->option_id,
                        'record_title'=> 'Option: ' . $opt->option_name,
                        'field'       => 'option_value',
                        'threat_id'   => $p['id'],
                        'threat_name' => $p['name'],
                        'severity'    => $p['severity'],
                        'snippet'     => $snippet
                    ];
                }
            }
        }

        // 3. Scan Comments Table
        $comments = $wpdb->get_results("SELECT comment_ID, comment_author, comment_content FROM {$wpdb->comments} WHERE comment_content != '' LIMIT 500");
        foreach ($comments as $com) {
            foreach ($patterns as $p) {
                if (preg_match($p['pattern'], $com->comment_content, $matches)) {
                    $snippet = substr($matches[0], 0, 160);
                    $findings[] = [
                        'table'       => 'comments',
                        'record_id'   => $com->comment_ID,
                        'record_title'=> 'Comment from: ' . $com->comment_author,
                        'field'       => 'comment_content',
                        'threat_id'   => $p['id'],
                        'threat_name' => $p['name'],
                        'severity'    => $p['severity'],
                        'snippet'     => $snippet
                    ];
                }
            }
        }

        return $findings;
    }

    /**
     * Clean/Remove a detected malicious snippet from a database record
     *
     * @param string $table 'posts', 'options', 'comments'
     * @param int $record_id
     * @param string $field
     * @param string $snippet
     * @return array Result
     */
    public static function clean_record($table, $record_id, $field, $snippet) {
        global $wpdb;

        if ($table === 'posts') {
            $row = $wpdb->get_row($wpdb->prepare("SELECT post_content FROM {$wpdb->posts} WHERE ID = %d", $record_id));
            if ($row) {
                $cleaned = str_replace($snippet, '', $row->post_content);
                $wpdb->update($wpdb->posts, ['post_content' => $cleaned], ['ID' => $record_id]);
                return ['success' => true, 'message' => __('Malicious database injection removed from post.', 'wp-shieldx')];
            }
        } elseif ($table === 'comments') {
            $wpdb->delete($wpdb->comments, ['comment_ID' => $record_id]);
            return ['success' => true, 'message' => __('Malicious spam comment deleted.', 'wp-shieldx')];
        } elseif ($table === 'options') {
            $row = $wpdb->get_row($wpdb->prepare("SELECT option_value FROM {$wpdb->options} WHERE option_id = %d", $record_id));
            if ($row) {
                $cleaned = str_replace($snippet, '', $row->option_value);
                $wpdb->update($wpdb->options, ['option_value' => $cleaned], ['option_id' => $record_id]);
                return ['success' => true, 'message' => __('Malicious payload cleaned from options table.', 'wp-shieldx')];
            }
        }

        return ['success' => false, 'message' => __('Target database record not found.', 'wp-shieldx')];
    }
}
