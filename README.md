# Cereus IPAM

IP Address Management plugin for [Cacti](https://www.cacti.net/) 1.2.x.

A ground-up rewrite of the legacy nmidPhpip plugin, built with modern security practices, full IPv4/IPv6 support, and a three-tier licensing model.

## Features

### Community (Free)
- IPv4 subnet management (up to 10 subnets)
- Manual IP address CRUD with 5-state tracking (active, reserved, DHCP, offline, available)
- Hierarchical section grouping
- Subnet utilization display with color-coded progress bars
- Dashboard with statistics, top utilization, and recent changes
- Subnet calculator (IPv4/IPv6 CIDR calculations)
- Tag management with custom colors and badge display
- Global search across all entities
- CSV import (up to 500 records) and export
- Cacti device auto-link via hostname matching
- Audit trail with CSV export (30-day retention)
- Device page integration (IPAM addresses box, subnet column)
- Migration tool from nmidPhpip

### Professional
- Unlimited subnets and import rows
- Full IPv6 support (dual-stack, GMP-based math)
- VLAN management with subnet-to-VLAN mapping
- VRF support for overlapping address spaces
- Network scanning: fping (poller), native ICMP ping, and parallel TCP probing (web) — supports /16 and larger subnets with chunked processing
- ARP table scanning via SNMP discovery
- DNS integration (forward/reverse lookups)
- Custom fields (text, textarea, dropdown, checkbox, date, URL)
- NAT mapping (inside/outside address documentation)
- Per-section RBAC (view/edit/admin permission levels)
- Threshold and conflict alerts with email notifications
- Notification list integration (additive to manual recipients)
- Reports: utilization, state summary, stale addresses, reconciliation
- Scheduled report emails (daily/weekly/monthly) with CSV attachment
- Bulk IP range fill
- Subnet nesting/hierarchy with auto-detection
- Advanced search with regex support
- Column filtering (VLAN, VRF, owner, device type, location)
- Import from phpIPAM and NetBox CSV formats
- Unlimited audit trail retention

### Enterprise
- Webhook callbacks (JSON POST on IPAM change events)
- REST API endpoints (via Cereus REST API plugin)
- Maintenance windows with scan/alert suppression
- Capacity forecasting (linear regression, exhaustion date prediction)
- Automated reconciliation (background job, discrepancy detection)
- DHCP scope monitoring via SNMP polling
- Multi-tenancy with tenant isolation per section
- Rack/location visualization (site/building/floor/room/rack hierarchy)
- Location assignment on IP addresses with filtering

## Platform Support

- **Linux** — Apache/Nginx, tested on RHEL/Rocky/Debian/Ubuntu
- **Windows** — IIS with PHP, tested on Windows Server 2019/2022

## Requirements

- Cacti 1.2.0 or higher
- PHP 8.1 or higher
- GMP PHP extension (required for IPv4/IPv6 calculations)
- MySQL/MariaDB with InnoDB support
- Optional: PHP sockets extension (for TCP network scanning)
- Optional: Cereus License Manager plugin (for Professional/Enterprise features)
- Optional: Cereus REST API plugin (for REST API endpoints)

## Installation

See the [INSTALL](INSTALL) file for detailed deployment instructions covering Linux, Windows/IIS, SELinux, firewall configuration, and troubleshooting.

### Quick Start (Linux)

1. Copy the `cereus_ipam` directory to `cacti/plugins/`
2. Set ownership: `chown -R apache:apache cacti/plugins/cereus_ipam/`
3. Enable via Cacti Console > Configuration > Plugins
4. Grant permissions to users via User Management > Realms
5. Navigate to Console > Configuration > Settings > IPAM to configure

## Upgrading from nmidPhpip

After installing Cereus IPAM, navigate to Console > Cereus Tools > IPAM Subnets and use the migration tool to import your existing nmidPhpip data. The original tables are preserved for safety.

## Security

- 100% prepared SQL statements (zero SQL injection surface)
- Input validation on all user data (IP, CIDR, MAC, hostname)
- CSRF protection via Cacti's built-in token system
- XSS prevention via html_escape() on all output
- Secure file upload handling (whitelist extensions, MIME check, size limit)
- Network scanning uses non-blocking sockets or OS ping command (shell arguments escaped via cacti_escapeshellarg)

## License

GPL-2.0-or-later

## Author

Thomas Urban / [Urban-Software.de](https://www.urban-software.com)
