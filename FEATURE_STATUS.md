# Cereus IPAM — Feature Status (v1.5.0)

## Community Tier (Free)

| Feature | Status |
|---------|--------|
| Hierarchical Sections (CRUD, nesting) | DONE |
| IPv4 Subnet Management (max 10 subnets) | DONE |
| IP Address CRUD with state management | DONE |
| CSV Import (500 row limit) / Export | DONE |
| Cacti Device Auto-Link (poller sync) | DONE |
| Utilization display (progress bars) | DONE |
| Dashboard (stats, top utilization, recent changes) | DONE |
| Subnet Calculator (IPv4/IPv6 CIDR) | DONE |
| Tag Management (create, assign, color badges) | DONE |
| Global Search (basic LIKE) | DONE |
| Changelog / Audit Log (30-day retention, CSV export) | DONE |
| Settings tab with collapsible sections | DONE |
| Migration from nmidPhpip | DONE |
| Device page integration (IPAM box, subnet column) | DONE |

## Professional Tier

| Feature | Status |
|---------|--------|
| Unlimited subnets & imports | DONE |
| Full IPv6 / Dual-Stack | DONE |
| VLAN Management (CRUD, subnet mapping) | DONE |
| VRF Management (CRUD, overlapping spaces) | DONE |
| Network Scanning (fping + native ping + TCP parallel fallback) | DONE |
| Live Scan Feed (real-time scrolling IP status display) | DONE |
| Stop Scan (cancel running scans, partial results preserved) | DONE |
| Scan Results Pagination (server-side, large subnet support) | DONE |
| ARP Table Scanning (SNMP discovery) | DONE |
| DNS integration (forward/reverse lookup) | DONE |
| Custom Fields (6 types: text, textarea, dropdown, checkbox, date, url) | DONE |
| NAT Mapping (inside/outside fields + display) | DONE |
| Per-Section RBAC (view/edit/admin) | DONE |
| Threshold Alerts (email with cooldown, notification lists) | DONE |
| Conflict Detection Alerts (email, notification lists) | DONE |
| Reports: Utilization, State Summary, Stale, Reconciliation | DONE |
| Reports: CSV Export | DONE |
| Scheduled Report Emails (daily/weekly/monthly, CSV attachment) | DONE |
| Notification List integration (all alert types) | DONE |
| Bulk IP Range Fill | DONE |
| Subnet Nesting / Hierarchy (parent auto-detection) | DONE |
| Advanced Search (regex support) | DONE |
| Column Filtering (VLAN, VRF, owner, device type, location) | DONE |
| Import from phpIPAM and NetBox CSV formats | DONE |
| Unlimited changelog retention | DONE |
| Visual Network Map — Tile Map (d3.js, /24 overview, per-IP grid, drill-down) | DONE |
| Reports: PDF Export (TCPDF) | NOT YET |

## Enterprise Tier

| Feature | Status |
|---------|--------|
| Hilbert Curve Heatmap (d3.js, space-filling, full /16 at a glance) | DONE |
| Webhook Callbacks (JSON POST, test button) | DONE |
| REST API Endpoints (sections, subnets, addresses, VLANs, VRFs) | DONE |
| Maintenance Windows (scan/alert suppression) | DONE |
| Capacity Forecasting (linear regression, dashboard widget) | DONE |
| Automated Reconciliation (poller job, discrepancy tracking) | DONE |
| DHCP Scope Monitoring (SNMP polling) | DONE |
| Multi-Tenancy (tenant isolation per section) | DONE |
| Rack / Location Visualization (site/building/floor/room/rack) | DONE |
| Location assignment on IP addresses with filter | DONE |
| LDAP/AD group-to-permission mapping | STUB |
