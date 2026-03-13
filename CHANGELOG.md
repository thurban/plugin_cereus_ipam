# Changelog

## [1.6.0] - 2026-03-13

### Fixed
- **Nmap/fping broken on Windows** — `cacti_escapeshellcmd()` replaces backslashes with spaces, destroying paths like `C:\Program Files (x86)\Nmap\nmap.exe`; new `cereus_ipam_escape_binary_path()` helper uses `cacti_escapeshellarg()` (quoting) on Windows instead; stderr redirect `2>` also fixed for Windows paths with spaces; `is_executable()` replaced with `file_exists()` for Windows .exe detection
- **Nmap scan completion detection** — nmap `-sn` only reports UP hosts in its XML `<host>` elements, so the scan appeared stuck at a low percentage (e.g. 10/254 = 4%) even after nmap finished; now parses `<runstats><hosts total="N"/>` for the correct count and inserts DB records for down hosts so progress tracking shows 100%
- **Scan completion not detected by UI** — progress poller's 5-second race guard could prevent fast scans from being recognized as complete; now uses the persisted scan result as a definitive completion signal with no time guard needed
- **Live scan feed flooded with "no response" entries** — nmap down-host records overwhelmed the feed; live feed now only shows alive hosts (server-side filtered), while stats bar still shows accurate totals
- **Duplicate scan start possible** — server-side guard now rejects scan requests when one is already running for the same subnet
- **Crashed scans block future scans** — added `register_shutdown_function()` to clear scan flags on fatal errors, plus heartbeat-based stale detection (2-minute timeout) with automatic cleanup
- **Race window between result persist and flag clear** — scan result is now persisted BEFORE the active flag is cleared, preventing the progress poller from seeing an incomplete state
- **Missing `tenant_id` column** — `plugin_cereus_ipam_sections.tenant_id` was not added on existing installs; setup.php migration now runs on plugin upgrade
- **DHCP scope monitoring crash** — `cacti_snmp_get()` was called without loading the SNMP library first
- **License check redeclare error** — added include guard to `license_check.php` to prevent "Cannot redeclare" fatal errors

### Added
- **Nmap scan method** — new `-sn` ping scan option using nmap for high-confidence host discovery; auto-detects nmap binary, configurable path in settings
- **Dashboard-style scan results** — visual summary with stat cards (alive, no response, total, duration), ratio progress bar, scan method/command details, and error reporting
- **Running scan detection on page load** — Network Scan page detects if a scan is already in progress and auto-enters scanning state with progress polling
- **Force clear stale scan** — manual "Clear Stale Scan" button to recover from stuck scan state
- **Deferred conflict detection** — conflict check now runs after the HTTP response is flushed via `fastcgi_finish_request()`, so the scan result dashboard appears immediately
- **Nmap settings** — configurable nmap binary path in IPAM settings tab

### Changed
- Scan progress poller uses `MAX(id)` for feed cursor advancement instead of iterating all rows
- Nmap scan results include down hosts in the database for accurate progress tracking
- `scanFinished()` is now idempotent — safe when both the POST response and progress poller trigger completion simultaneously

## [1.5.0] - 2026-03-13

### Fixed
- **Device list disappearing** — installing Cereus IPAM caused all devices to vanish from Management > Devices
  - Root cause: `device_table_replace` hook must render complete HTML rows when `device_display_text` adds columns; previous implementation only enriched the `$hosts` array without outputting HTML
  - Now renders all standard Cacti device columns (description, hostname, ID, graphs, data sources, status, uptime, polling time, current/average time, availability) plus the IPAM Subnet column
- **Scan results pagination** — clicking page links always showed page 1
  - Switched from AJAX injection (`return_to`) to standard Cacti `document.location` page navigation
  - Uses `load_current_session_value` with standard `page` variable for proper session persistence
- **Show/hide "No Response" checkbox** — checkbox had no effect after AJAX page loads
  - jQuery `.change()` event binding fails in AJAX-injected content; replaced with inline `onchange` handler

### Added
- **Live scan feed** — real-time scrolling display of scanned IPs with color-coded alive/dead status during scan execution
  - Terminal-style dark panel with green (alive) and grey (no response) indicators
  - Auto-scrolls with manual scroll-up detection
  - Progress bar with scanned/total/alive counters
- **Stop scan** — cancel a running scan via red "Stop Scan" button
  - Server-side stop flag checked between scan chunks (fping, native ping, and TCP parallel)
  - Partial results preserved; conflict detection skipped on incomplete scans
- **Server-side pagination** for scan results — handles large subnets (/16+) without browser lockup
  - SQL LIMIT/OFFSET with proper page clamping
  - "No Response" hosts hidden by default, toggled via checkbox with server-side filtering

### Changed
- Scan results table fully server-side rendered with `INET_ATON()` IP sorting
- Scan progress endpoint returns incremental results via `last_id` cursor for live feed
- Scanner functions return `stopped` flag in result array

## [1.4.0] - 2026-03-12

### Added
- **Visual Network Map** — interactive d3.js subnet visualization (Professional+)
  - Tile Map: /24 block overview grid with utilization heatmap for large subnets (/16-/21)
  - Per-IP grid: color-coded blocks for individual IPs (/22-/32)
  - Drill-down: click any /24 tile to expand into per-IP view
  - Tooltips: hover to see IP, hostname, MAC, owner, state
  - Click any IP block to edit or create an address
  - Conflict detection: rogue IPs shown in orange
  - PNG export for all views
- **Hilbert Curve Heatmap** — space-filling curve visualization (Enterprise)
  - Renders entire /16 (65,536 IPs) in a single compact view
  - Preserves IP adjacency — nearby IPs stay near each other visually
  - Canvas-based rendering for performance with large datasets
  - SVG rendering with full interactivity for /24 and smaller
  - Same tooltips and click-to-edit as tile map
- License gating: Visual Map requires Professional, Hilbert requires Enterprise
  - Community users see upgrade prompt with lock icon
  - Professional users see Hilbert toggle disabled with Enterprise prompt
- Subnet list quick-action icons now license-gated (Visual Map icon only shown for Professional+)

## [1.3.0] - 2026-03-12

### Fixed
- Large subnet scanning (/16 and above) now completes reliably on all platforms
  - Native ICMP ping scanner rewritten with /24-sized chunking (was building all 65,536 IPs into memory at once)
  - fping scanner split into /24 chunks for subnets larger than /24 with progressive result storage
  - Scan results written to database after each chunk, not held in memory until completion
- Scans no longer silently abort when HTTP connection drops
  - Added `ignore_user_abort(true)` to both ping and ARP scan entry points
  - Works across Apache (Timeout), Nginx (proxy_read_timeout), and IIS FastCGI (ActivityTimeout)
  - ARP scan entry point now also sets `set_time_limit(0)` for consistency

### Changed
- Scan UI: HTTP timeout no longer shows a failure message — instead displays "Scan running in background" and continues polling until the scan completes
- Progress heartbeat frequency increased (every 4 chunks of 256 IPs) for more responsive progress display on large subnets
- Native ping scanner memory usage reduced from O(subnet_size) to O(256) for large subnets

## [1.2.0] - 2026-03-12

### Fixed
- ARP scan fatal error: `Call to undefined function cacti_snmp_walk()` — Cacti's SNMP library is now loaded before ARP table walks

### Added
- Native ICMP ping scan method using the OS `ping` command
  - Works on Windows (`ping -n 1 -w <timeout>`) and Linux (`ping -c 1 -W <timeout>`)
  - IPv6 support via `ping -6` (Windows) and `ping6` (Linux)
  - Parallel execution using `proc_open()` (batches of 20 concurrent pings)
  - Latency extraction from ping output
  - Available as explicit "Native Ping" setting or auto-selected on Windows when fping is unavailable
- New scan method option in settings: "Native Ping (ICMP via OS ping command)"
- Single-host ping now uses native ICMP on Windows for more accurate alive detection

### Changed
- Auto scan method detection now prefers native ICMP ping over TCP on Windows (devices without open TCP ports are no longer missed)
- Scan method setting description updated to reflect the new ping option

## [1.1.0] - 2026-03-12

### Fixed
- Network scanning now supports large subnets (e.g. /16) — previously only /24 worked
  - TCP scanner processes subnets in /24-sized chunks instead of truncating at 1024 IPs
  - Scan progress reports actual subnet size instead of capping at 256
  - PHP execution time limit removed during scans to prevent timeout on large subnets
  - AJAX and progress-poll timeouts extended to 30 minutes for large scans
  - Scanner sends periodic heartbeat during chunked scans for accurate progress display
- False positive conflict alerts eliminated
  - MAC address comparison now normalizes format (strips separators) before comparing
  - Stale detection skips addresses that were never confirmed alive (no last_seen)
  - Rogue detection excludes known Cacti device IPs (device sync handles those)
  - Conflict alert emails now filtered by user-selected conflict types
- ARP scan (SNMP) now finds devices reliably
  - Matches devices with status UP or Recovering (was UP only)
  - Requires SNMP version > 0 to skip non-SNMP devices
  - Resolves gateway DNS names to IP for proper device matching
  - Falls back to matching by both raw hostname and resolved IP
  - Provides detailed error messages with actionable troubleshooting hints

### Added
- New setting "Alert on Conflict Types" — multi-select to choose which conflict types (MAC, Rogue, Stale) trigger email alerts (default: MAC Conflict only)

## [1.0.1] - 2026-03-12

### Added
- Comprehensive INSTALL guide covering Linux and Windows/IIS deployment
- PHP extension pre-flight checks on plugin enable (GMP required, sockets recommended)

### Changed
- Network scanner now fully compatible with Windows/IIS environments
  - Platform-aware fping binary detection (Windows paths, Cacti base dir, PATH)
  - Portable shell escaping via cacti_escapeshellcmd() / cacti_escapeshellarg()
  - Windows stderr redirect handling (skip unsupported 2>&1)
  - Winsock error code mapping for TCP connect scanning (10061/10036/10035)
  - Graceful fallback when PHP sockets extension is unavailable
- Updated settings descriptions to document Windows/IIS behavior and paths
- fping path setting now shows example paths for both Linux and Windows

### Fixed
- TCP connect scanner hardcoded Unix errno values (111, 115) now use platform-correct codes
- Socket extension guard prevents fatal errors on hosts without ext-sockets

## [1.0.0] - 2026-03-11

### Added

#### Core
- Ground-up rewrite of the legacy nmidPhpip plugin for Cacti 1.2.x
- 100% prepared SQL statements — zero SQL injection surface
- Input validation for all user data (IP, CIDR, MAC, hostname, state)
- CSRF protection via Cacti's built-in token system
- XSS prevention via html_escape() on all output
- 17 InnoDB database tables with utf8mb4 collation
- Three-tier license gating (Community / Professional / Enterprise)
- PHP 8.1+ and Cacti 1.2.0+ compatibility

#### Community Tier
- Hierarchical section management for organizing subnets
- IPv4 subnet management with CIDR notation (max 10 subnets)
- IP address CRUD with 5-state tracking (active, reserved, DHCP, offline, available)
- Subnet utilization display with color-coded progress bars
- CSV import (up to 500 records) with validation and error reporting
- CSV export for IP addresses per subnet
- Cacti device auto-link: match host.hostname to IP records on each poller cycle
- Dashboard page: statistics, top 10 utilization, address state distribution, recent changes
- Subnet calculator: full CIDR calculations for IPv4 and IPv6
- Tag management: create tags with custom colors, assign to subnets and addresses
- Global search across sections, subnets, and addresses
- Full audit trail with CSV export (30-day retention)
- Settings tab with collapsible feature sections
- Migration tool from nmidPhpip (sections, subnets, addresses)
- Device page integration: IPAM addresses box on device edit, IPAM subnet column on device list

#### Professional Tier
- Unlimited subnets and import rows
- Full IPv6 / dual-stack support (GMP-based math)
- VLAN management (CRUD) with subnet-to-VLAN mapping
- VRF support for overlapping address spaces
- Network scanning via fping (poller) and parallel TCP probing (web)
- ARP table scanning via SNMP (ipNetToMediaTable)
- DNS integration: forward and reverse lookups in address views
- Custom fields: 6 types (text, textarea, dropdown, checkbox, date, URL) for subnets, addresses, VLANs
- NAT mapping: inside/outside address documentation
- Per-section RBAC: view, edit, admin permission levels
- Threshold alerts: email notifications when subnet utilization exceeds configured percentage
- Conflict detection alerts: email notifications for new IP conflicts after scans
- Notification list integration for all alert types (additive to manual recipients)
- Reports: subnet utilization, address state summary, stale addresses, reconciliation
- Scheduled report emails: daily/weekly/monthly with CSV attachment
- Bulk IP range fill: populate address ranges with common attributes
- Subnet nesting with automatic parent-child detection
- Advanced search with regex support
- Column filtering: VLAN, VRF, owner, device type, location
- Import from phpIPAM and NetBox CSV formats
- Unlimited audit trail retention

#### Enterprise Tier
- Webhook callbacks: JSON POST to configured URLs on IPAM change events
- Webhook test button on settings page
- REST API endpoints for sections, subnets, addresses, VLANs, VRFs (via restapi plugin)
- Maintenance windows with scan and alert suppression
- Capacity forecasting: linear regression predicting subnet exhaustion dates
- Automated reconciliation: background job detecting alive-but-unmanaged, stale, and hostname mismatches
- DHCP scope monitoring via SNMP polling
- Multi-tenancy: tenant isolation per section with user-to-tenant assignment
- Rack/location visualization: hierarchical tree (site, building, floor, room, rack)
- Location assignment on IP addresses with filtering
