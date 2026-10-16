=== WP ShieldX - Advanced Security, File Monitor & Firewall ===
Contributors: saiarlen
Donate link: https://www.saiarlen.com
Tags: security, file monitor, malware scanner, firewall, waf, quarantine, repair
Requires at least: 5.8
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Next-generation WordPress cybersecurity suite: Real-time File Integrity Monitor (added/modified/deleted files), Deep Malware & Weird Pattern Heuristic Scanner with WordPress.org Core Checksums API, Active Request Firewall (WAF), Instant Email Attack Alerts, and One-Click File Quarantine & Core Repair.

== Description ==

**WP ShieldX** is an enterprise-grade WordPress cybersecurity plugin designed to deliver proactive defense, deep file integrity auditing, and automated remediation without slowing down your site.

### Key Features

1. **Full File Integrity Monitor (FIM)**:
   * **Tracks Added, Modified, and Deleted Files**: Takes cryptographic SHA-256 snapshots of your entire WordPress directory structure.
   * **Interactive File Monitor Dashboard**: Review modified diffs, detect stealth injections into `functions.php` or `index.php`, and catch rogue scripts dropped into `wp-content/uploads/`.
   * **Direct Remediation Actions**:
     - *Quarantine*: Move suspicious files immediately into an isolated vault where execution privileges are revoked.
     - *Repair Core*: One-click replacement of damaged or backdoored official WordPress core files directly from WordPress.org.
     - *Accept / Whitelist*: Accept verified developer changes into the new baseline snapshot.
     - *Permanent Delete*: Erase malicious scripts in one click.

2. **Deep Malware & Weird Pattern Scanner**:
   * **WordPress.org Core Checksums API Integration**: Fetches official release hashes from `api.wordpress.org` and verifies every core file against tampering.
   * **Heuristic Pattern & Webshell Detection**: Scans for obfuscations (`eval(base64_decode())`, `preg_replace /e`, `create_function`), known webshell signatures (c99, r57, WSO, b374k, FilesMan), and direct shell invocations (`system($_POST...)`).
   * **Shannon Entropy Analysis**: Detects packed, encrypted, or heavily obfuscated string payloads.
   * **Unauthorized Uploads Execution Detection**: Flags executable scripts residing inside media folders.

3. **Active Web Application Firewall (WAF)**:
   * **Input Vector Inspection**: Inspects `GET`, `POST`, `COOKIE`, `REQUEST_URI`, and raw inputs.
   * **SQL Injection (SQLi) Defense**: Stops UNION SELECT, blind boolean, and time-based sleep/benchmark attacks.
   * **Cross-Site Scripting (XSS) Shield**: Prevents reflected and stored script tags, SVG vectors, and event handler injections.
   * **LFI / RFI & Directory Traversal**: Halts `../` traversal, `/etc/passwd` reading, and `php://input` stream wrappers.
   * **Vulnerability Scanner Blocker**: Blocks automated attack tools (sqlmap, nikto, wpscan, gobuster).
   * **Brute-Force & XML-RPC Hardening**: Rate limits failed logins and blocks unauthenticated user enumeration (`/?author=1` & REST API).

4. **Instant Email Attack Notifications**:
   * Sends modern, responsive HTML incident reports to site administrators when high-severity firewall attacks, unauthorized file modifications, or malware backdoors are detected.
   * Includes attack classification, client IP, affected file path, and direct links to take action.

5. **Quarantine Vault & Safe Remediation**:
   * Quarantined files are moved to `wp-content/uploads/wp-shieldx-quarantine/` with access restricted via `.htaccess` (`Deny from all`) and `index.php`.
   * Files can be restored back to their exact original path if determined to be false positives.

== Installation ==

1. Upload the `wp-shieldx` folder to the `/wp-content/plugins/` directory, or install the `.zip` archive via WordPress Admin > Plugins > Add New > Upload Plugin.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Upon activation, WP ShieldX automatically establishes the database schema, creates the quarantine vault, and indexes your files into an initial baseline.
4. Navigate to **WP ShieldX** in the WordPress admin menu to review your security dashboard.

== Frequently Asked Questions ==

= How does the File Monitor detect new or modified files? =
WP ShieldX computes SHA-256 cryptographic hashes and modification timestamps for all monitored files and stores them in a local baseline table. During automated or manual integrity scans, files on disk are compared against the baseline to isolate added, modified, or deleted files.

= What happens when I quarantine a file? =
The file is moved into an isolated vault, given read-only permissions (`0400`), and hidden behind an `.htaccess` execution barrier. The original location and permissions are recorded in the database, allowing you to restore it at any time.

= How does Core Repair work? =
WP ShieldX connects to the official WordPress.org releases and downloads the authentic, clean file matching your exact WordPress version. It first backs up the tampered file to quarantine, then replaces it with the pristine version.

== Changelog ==

= 1.0.0 =
* Initial release of WP ShieldX Security Suite.
* Real-time File Integrity Monitor (added/modified/deleted).
* Deep Malware & Weird Pattern Heuristics Engine.
* Official WordPress.org Core Checksums API integration.
* Active Request Firewall (WAF) with SQLi, XSS, RFI/LFI, and Bot blocking.
* Instant HTML email attack notification engine.
* One-click file quarantine vault and core file repair.
