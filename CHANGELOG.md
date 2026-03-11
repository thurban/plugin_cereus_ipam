# Changelog

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
