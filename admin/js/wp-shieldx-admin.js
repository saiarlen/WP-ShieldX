/**
 * WP ShieldX Admin JavaScript
 * Handles interactive file monitoring, deep malware scans, quarantine vault, and settings.
 */

(function($) {
    'use strict';

    $(document).ready(function() {

        // 1. Rebuild Baseline Snapshot
        $(document).on('click', '#btn-rebuild-baseline', function(e) {
            e.preventDefault();
            var $btn = $(this);
            var originalText = $btn.html();
            $btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> Rebuilding Baseline...');

            $.post(wpShieldXData.ajax_url, {
                action: 'wp_shieldx_rebuild_baseline',
                nonce: wpShieldXData.nonce
            }, function(response) {
                $btn.prop('disabled', false).html(originalText);
                if (response.success) {
                    alert(response.data.message);
                    window.location.reload();
                } else {
                    alert('Error: ' + (response.data.message || 'Failed to rebuild baseline.'));
                }
            }).fail(function() {
                $btn.prop('disabled', false).html(originalText);
                alert('Connection error while rebuilding baseline.');
            });
        });

        // 2. Check File Integrity Now
        $(document).on('click', '#btn-quick-check-integrity, #btn-run-fim', function(e) {
            e.preventDefault();
            var $btn = $(this);
            var originalText = $btn.html();
            $btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> Checking Integrity...');

            $.post(wpShieldXData.ajax_url, {
                action: 'wp_shieldx_check_integrity',
                nonce: wpShieldXData.nonce
            }, function(response) {
                $btn.prop('disabled', false).html(originalText);
                if (response.success) {
                    var data = response.data;
                    var summary = 'File Integrity Scan Complete:\n' +
                                  '- Added Files: ' + data.added + '\n' +
                                  '- Modified Files: ' + data.modified + '\n' +
                                  '- Deleted Files: ' + data.deleted + '\n' +
                                  '- Clean Baseline Files: ' + data.clean;
                    alert(summary);
                    window.location.reload();
                } else {
                    alert('Error running file integrity scan.');
                }
            }).fail(function() {
                $btn.prop('disabled', false).html(originalText);
                alert('Connection error during file scan.');
            });
        });

        // 3. Progressive Batch Malware Scanner
        $(document).on('click', '#btn-start-malware-scan', function(e) {
            e.preventDefault();
            var $btn = $(this);
            $btn.prop('disabled', true);
            $('#scan-progress-box').fadeIn(200);

            var offset = 0;
            var limit = 40;
            var totalThreatsFound = 0;

            function runScanBatch() {
                $.post(wpShieldXData.ajax_url, {
                    action: 'wp_shieldx_run_malware_scan',
                    nonce: wpShieldXData.nonce,
                    offset: offset,
                    limit: limit
                }, function(response) {
                    if (response.success) {
                        var res = response.data;
                        offset = res.processed;
                        totalThreatsFound += res.threats_found;

                        var percent = res.total_files > 0 ? Math.min(100, Math.round((offset / res.total_files) * 100)) : 100;
                        $('#scan-progress-fill').css('width', percent + '%');
                        $('#scan-counter').text(offset + ' / ' + res.total_files + ' files (' + percent + '%)');

                        if (!res.completed && offset < res.total_files) {
                            runScanBatch();
                        } else {
                            $('#scan-status-text').text(wpShieldXData.strings.scan_complete);
                            $btn.prop('disabled', false);
                            setTimeout(function() {
                                alert('Deep Malware Scan Complete!\nProcessed: ' + offset + ' files.\nThreats Found: ' + totalThreatsFound);
                                window.location.reload();
                            }, 500);
                        }
                    } else {
                        alert('Scan stopped due to an error: ' + (response.data ? response.data.message : 'Unknown error'));
                        $btn.prop('disabled', false);
                    }
                }).fail(function() {
                    alert('Network error while scanning.');
                    $btn.prop('disabled', false);
                });
            }

            runScanBatch();
        });

        // 4. Quarantine File Action
        $(document).on('click', '.btn-action-quarantine', function(e) {
            e.preventDefault();
            var filePath = $(this).data('path');
            if (!confirm(wpShieldXData.strings.confirm_quarantine + '\n' + filePath)) {
                return;
            }

            var $row = $(this).closest('tr');
            $.post(wpShieldXData.ajax_url, {
                action: 'wp_shieldx_quarantine_file',
                nonce: wpShieldXData.nonce,
                file_path: filePath
            }, function(res) {
                if (res.success) {
                    alert(res.data.message);
                    $row.fadeOut(300, function() { $(this).remove(); });
                } else {
                    alert('Error: ' + res.data.message);
                }
            });
        });

        // 5. Restore Quarantined File
        $(document).on('click', '.btn-action-restore', function(e) {
            e.preventDefault();
            var qId = $(this).data('id');
            var $row = $(this).closest('tr');

            $.post(wpShieldXData.ajax_url, {
                action: 'wp_shieldx_restore_quarantined',
                nonce: wpShieldXData.nonce,
                quarantine_id: qId
            }, function(res) {
                if (res.success) {
                    alert(res.data.message);
                    $row.fadeOut(300, function() { $(this).remove(); });
                } else {
                    alert('Error: ' + res.data.message);
                }
            });
        });

        // 6. Repair WordPress Core File from Official WordPress.org
        $(document).on('click', '.btn-action-repair-core', function(e) {
            e.preventDefault();
            var relative = $(this).data('relative');
            if (!confirm(wpShieldXData.strings.confirm_repair + '\n' + relative)) {
                return;
            }

            var $row = $(this).closest('tr');
            $.post(wpShieldXData.ajax_url, {
                action: 'wp_shieldx_repair_core',
                nonce: wpShieldXData.nonce,
                relative_path: relative
            }, function(res) {
                if (res.success) {
                    alert(res.data.message);
                    window.location.reload();
                } else {
                    alert('Error: ' + res.data.message);
                }
            });
        });

        // Manual Core Repair Input
        $(document).on('click', '#btn-manual-repair', function(e) {
            e.preventDefault();
            var path = $.trim($('#manual-repair-path').val());
            if (!path) {
                alert('Please enter a core file relative path.');
                return;
            }

            var $btn = $(this);
            $btn.prop('disabled', true);

            $.post(wpShieldXData.ajax_url, {
                action: 'wp_shieldx_repair_core',
                nonce: wpShieldXData.nonce,
                relative_path: path
            }, function(res) {
                $btn.prop('disabled', false);
                if (res.success) {
                    alert(res.data.message);
                    window.location.reload();
                } else {
                    alert('Error: ' + res.data.message);
                }
            }).fail(function() {
                $btn.prop('disabled', false);
                alert('Connection error downloading core file.');
            });
        });

        // 7. Permanently Delete Malicious File
        $(document).on('click', '.btn-action-delete', function(e) {
            e.preventDefault();
            var filePath = $(this).data('path');
            if (!confirm(wpShieldXData.strings.confirm_delete + '\n' + filePath)) {
                return;
            }

            var $row = $(this).closest('tr');
            $.post(wpShieldXData.ajax_url, {
                action: 'wp_shieldx_delete_file',
                nonce: wpShieldXData.nonce,
                file_path: filePath
            }, function(res) {
                if (res.success) {
                    alert(res.data.message);
                    $row.fadeOut(300, function() { $(this).remove(); });
                } else {
                    alert('Error: ' + res.data.message);
                }
            });
        });

        // 8. Whitelist / Accept File Changes
        $(document).on('click', '.btn-action-whitelist', function(e) {
            e.preventDefault();
            var filePath = $(this).data('path');
            var $row = $(this).closest('tr');

            $.post(wpShieldXData.ajax_url, {
                action: 'wp_shieldx_whitelist_file',
                nonce: wpShieldXData.nonce,
                file_path: filePath
            }, function(res) {
                if (res.success) {
                    alert(res.data.message);
                    $row.fadeOut(300, function() { $(this).remove(); });
                } else {
                    alert('Error: ' + res.data.message);
                }
            });
        });

        // 9. Lockdown Uploads Folder
        $(document).on('click', '#btn-lockdown-uploads', function(e) {
            e.preventDefault();
            $.post(wpShieldXData.ajax_url, {
                action: 'wp_shieldx_lockdown_uploads',
                nonce: wpShieldXData.nonce
            }, function(res) {
                alert(res.data.message);
            });
        });

        // 10. Clear Logs Handlers
        $(document).on('click', '#btn-clear-firewall-logs', function(e) {
            e.preventDefault();
            if (!confirm('Are you sure you want to clear all firewall logs?')) return;
            $.post(wpShieldXData.ajax_url, {
                action: 'wp_shieldx_clear_firewall_logs',
                nonce: wpShieldXData.nonce
            }, function(res) {
                alert(res.data.message);
                window.location.reload();
            });
        });

        $(document).on('click', '#btn-clear-scan', function(e) {
            e.preventDefault();
            if (!confirm('Clear scan results?')) return;
            $.post(wpShieldXData.ajax_url, {
                action: 'wp_shieldx_clear_scan_results',
                nonce: wpShieldXData.nonce
            }, function(res) {
                alert(res.data.message);
                window.location.reload();
            });
        });

        // 11. Save Settings Form
        $('#wps-settings-form').on('submit', function(e) {
            e.preventDefault();
            var $form = $(this);
            var $status = $('#save-status');
            var formData = $form.serialize() + '&action=wp_shieldx_save_settings&nonce=' + wpShieldXData.nonce;

            $status.css('color', '#0284c7').text('Saving configurations...');

            $.post(wpShieldXData.ajax_url, formData, function(res) {
                if (res.success) {
                    $status.css('color', '#16a34a').text('Settings saved successfully!');
                    setTimeout(function() { $status.text(''); }, 3000);
                } else {
                    $status.css('color', '#dc2626').text('Error saving settings.');
                }
            }).fail(function() {
                $status.css('color', '#dc2626').text('Server communication error.');
            });
        });

        // 12. Database Threat & SEO Scanner
        $(document).on('click', '#btn-start-db-scan', function(e) {
            e.preventDefault();
            var $btn = $(this);
            $btn.prop('disabled', true);
            $('#db-scan-status-box').fadeIn(200);

            $.post(wpShieldXData.ajax_url, {
                action: 'wp_shieldx_scan_database',
                nonce: wpShieldXData.nonce
            }, function(res) {
                $btn.prop('disabled', false);
                $('#db-scan-status-box').hide();

                if (res.success) {
                    var findings = res.data.findings || [];
                    $('#db-threat-count').text(findings.length);

                    if (findings.length === 0) {
                        $('#db-empty-state').show().html('<div class="empty-icon text-success">&#10004;</div><h3>Clean Database: No Injections Detected</h3><p>No malicious scripts, iframes, or SEO spam redirects found in posts, options, or comments.</p>');
                        $('#db-findings-table').hide();
                    } else {
                        $('#db-empty-state').hide();
                        var tbody = '';
                        findings.forEach(function(item) {
                            var sevBadge = item.severity === 'critical' ? 'badge-danger' : 'badge-warning';
                            tbody += '<tr>' +
                                '<td><span class="badge ' + sevBadge + '">' + item.severity.toUpperCase() + '</span></td>' +
                                '<td><strong>' + item.threat_name + '</strong></td>' +
                                '<td><code>' + item.table + '</code> &bull; ' + item.record_title + '</td>' +
                                '<td><pre class="code-snippet"><code>' + $('<div>').text(item.snippet).html() + '</code></pre></td>' +
                                '<td style="text-align: right;"><button class="wps-btn-mini wps-btn-danger btn-action-clean-db" data-table="' + item.table + '" data-id="' + item.record_id + '" data-field="' + item.field + '" data-snippet="' + encodeURIComponent(item.snippet) + '">Clean Payload</button></td>' +
                                '</tr>';
                        });
                        $('#db-findings-body').html(tbody);
                        $('#db-findings-table').fadeIn(200);
                    }
                } else {
                    alert('Error scanning database.');
                }
            }).fail(function() {
                $btn.prop('disabled', false);
                $('#db-scan-status-box').hide();
                alert('Database scan request failed.');
            });
        });

        // Clean DB Record Action
        $(document).on('click', '.btn-action-clean-db', function(e) {
            e.preventDefault();
            var $btn = $(this);
            var $row = $btn.closest('tr');

            $.post(wpShieldXData.ajax_url, {
                action: 'wp_shieldx_clean_db_record',
                nonce: wpShieldXData.nonce,
                table_name: $btn.data('table'),
                record_id: $btn.data('id'),
                field: $btn.data('field'),
                snippet: decodeURIComponent($btn.data('snippet'))
            }, function(res) {
                if (res.success) {
                    alert(res.data.message);
                    $row.fadeOut(300, function() { $(this).remove(); });
                } else {
                    alert('Error: ' + res.data.message);
                }
            });
        });

        // 13. Hardening Form Save
        $('#wps-hardening-form').on('submit', function(e) {
            e.preventDefault();
            var $form = $(this);
            var $status = $('#harden-status');
            var formData = $form.serialize() + '&action=wp_shieldx_save_hardening&nonce=' + wpShieldXData.nonce;

            $status.css('color', '#0284c7').text('Applying hardening policies...');

            $.post(wpShieldXData.ajax_url, formData, function(res) {
                if (res.success) {
                    $status.css('color', '#16a34a').text('Policies enforced!');
                    setTimeout(function() { $status.text(''); }, 3000);
                } else {
                    $status.css('color', '#dc2626').text('Error enforcing policies.');
                }
            }).fail(function() {
                $status.css('color', '#dc2626').text('Server communication error.');
            });
        });

        // 14. Refresh Plugin Vulnerability Audit
        $(document).on('click', '#btn-refresh-plugin-audit', function(e) {
            e.preventDefault();
            var $btn = $(this);
            $btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> Checking WordPress.org...');

            $.post(wpShieldXData.ajax_url, {
                action: 'wp_shieldx_audit_plugins',
                nonce: wpShieldXData.nonce,
                refresh: 1
            }, function(res) {
                $btn.prop('disabled', false).html('<span class="dashicons dashicons-update"></span> Re-Check Plugins Registry');
                if (res.success) {
                    alert('Plugin Vulnerability Audit complete!');
                    window.location.reload();
                } else {
                    alert('Error checking plugin vulnerabilities.');
                }
            }).fail(function() {
                $btn.prop('disabled', false);
                alert('Connection error to WordPress.org.');
            });
        });

        // 15. 1-Click Rollback Snapshot
        $(document).on('click', '.btn-action-rollback', function(e) {
            e.preventDefault();
            if (!confirm('Warning: This will restore the extension files from this backup snapshot. Proceed with rollback?')) {
                return;
            }

            var $btn = $(this);
            $btn.prop('disabled', true);

            $.post(wpShieldXData.ajax_url, {
                action: 'wp_shieldx_rollback_backup',
                nonce: wpShieldXData.nonce,
                backup_id: $btn.data('id')
            }, function(res) {
                $btn.prop('disabled', false);
                if (res.success) {
                    alert(res.data.message);
                    window.location.reload();
                } else {
                    alert('Error: ' + res.data.message);
                }
            });
        });

        // 16. Delete Backup Snapshot
        $(document).on('click', '.btn-action-delete-backup', function(e) {
            e.preventDefault();
            if (!confirm('Permanently delete this backup snapshot archive?')) {
                return;
            }

            var $row = $(this).closest('tr');
            $.post(wpShieldXData.ajax_url, {
                action: 'wp_shieldx_delete_backup',
                nonce: wpShieldXData.nonce,
                backup_id: $(this).data('id')
            }, function(res) {
                if (res.success) {
                    $row.fadeOut(300, function() { $(this).remove(); });
                }
            });
        });

    });

})(jQuery);
