# Changelog

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
