<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2024-2026 Urban-Software.de / Thomas Urban               |
 +-------------------------------------------------------------------------+
 | Cereus IPAM - Settings Tab                                              |
 +-------------------------------------------------------------------------+
*/

function cereus_ipam_config_settings() {
	global $tabs, $settings;

	include_once(__DIR__ . '/constants.php');
	include_once(__DIR__ . '/../lib/license_check.php');

	$tier = cereus_ipam_license_tier();

	/* Notification lists require thold plugin — check table exists */
	$has_notify_lists = db_table_exists('plugin_notification_lists');

	$tabs['cereus_ipam'] = __('IPAM', 'cereus_ipam');

	$settings['cereus_ipam'] = array(
		'cereus_ipam_general_header' => array(
			'friendly_name' => __('Cereus IPAM - General', 'cereus_ipam') . ' [' . ucfirst($tier) . ' ' . __('License', 'cereus_ipam') . ']',
			'method'        => 'spacer',
		),
		'cereus_ipam_enabled' => array(
			'friendly_name' => __('Enable IPAM', 'cereus_ipam'),
			'description'   => __('Enable or disable the IPAM plugin poller functions (device sync, scheduled scans).', 'cereus_ipam'),
			'method'        => 'checkbox',
			'default'       => 'on',
		),
		'cereus_ipam_device_sync' => array(
			'friendly_name' => __('Device Auto-Sync', 'cereus_ipam'),
			'description'   => __('Automatically link Cacti devices to IPAM address records by matching hostnames to IPs.', 'cereus_ipam'),
			'method'        => 'checkbox',
			'default'       => 'on',
		),
		'cereus_ipam_scan_header' => array(
			'friendly_name' => __('Network Scanning (Professional+)', 'cereus_ipam'),
			'method'        => 'spacer',
			'collapsible'   => 'true',
		),
		'cereus_ipam_scan_enabled' => array(
			'friendly_name' => __('Enable Scheduled Scans', 'cereus_ipam'),
			'description'   => __('Enable automatic scheduled network scanning for subnets with scanning enabled.', 'cereus_ipam'),
			'method'        => 'checkbox',
			'default'       => '',
		),
		'cereus_ipam_scan_concurrent' => array(
			'friendly_name' => __('Max Concurrent Scans', 'cereus_ipam'),
			'description'   => __('Maximum number of subnets to scan simultaneously during a poller cycle.', 'cereus_ipam'),
			'method'        => 'textbox',
			'default'       => '5',
			'max_length'    => 3,
			'size'          => 5,
		),
		'cereus_ipam_scan_method' => array(
			'friendly_name' => __('Scan Method', 'cereus_ipam'),
			'description'   => __('How to detect alive hosts. Auto uses fping from poller (fastest, requires raw sockets), native ping on Windows, and TCP connect as last resort. Ping uses the OS native ping command (ICMP) — works everywhere but is slower for large subnets. TCP uses parallel non-blocking socket connections. fping forces fping for all contexts (may fail from web UI under SELinux).', 'cereus_ipam'),
			'method'        => 'drop_array',
			'default'       => 'auto',
			'array'         => array(
				'auto'  => __('Auto (fping from poller, native ping on Windows, TCP fallback)', 'cereus_ipam'),
				'fping' => __('fping (requires raw socket capability)', 'cereus_ipam'),
				'ping'  => __('Native Ping (ICMP via OS ping command)', 'cereus_ipam'),
				'tcp'   => __('TCP Connect (works everywhere)', 'cereus_ipam'),
				'nmap'  => __('Nmap (-sn ping scan, high confidence, requires nmap)', 'cereus_ipam'),
			),
		),
		'cereus_ipam_fping_path' => array(
			'friendly_name' => __('fping Path', 'cereus_ipam'),
			'description'   => __('Path to the fping binary. Leave empty for auto-detection. Linux: /usr/sbin/fping, Windows: C:\\fping\\fping.exe or in PATH.', 'cereus_ipam'),
			'method'        => 'textbox',
			'default'       => '',
			'max_length'    => 255,
			'size'          => 40,
		),
		'cereus_ipam_nmap_path' => array(
		'friendly_name' => __('Nmap Path', 'cereus_ipam'),
		'description'   => __('Path to the nmap binary. Leave empty for auto-detection. Linux: /usr/bin/nmap, Windows: C:\\Program Files (x86)\\Nmap\\nmap.exe', 'cereus_ipam'),
		'method'        => 'textbox',
		'default'       => '',
		'max_length'    => 255,
		'size'          => 40,
	),
	'cereus_ipam_scan_tcp_ports' => array(
			'friendly_name' => __('TCP Probe Ports', 'cereus_ipam'),
			'description'   => __('Comma-separated list of TCP ports to probe when using TCP scan method. Ports are tried in order; scanning stops at first alive response per host.', 'cereus_ipam'),
			'method'        => 'textbox',
			'default'       => '80,443,22',
			'max_length'    => 128,
			'size'          => 30,
		),
		'cereus_ipam_scan_timeout' => array(
			'friendly_name' => __('Scan Timeout (ms)', 'cereus_ipam'),
			'description'   => __('Timeout in milliseconds for each scan batch. Lower values are faster but may miss slow-responding hosts. Range: 100-30000.', 'cereus_ipam'),
			'method'        => 'textbox',
			'default'       => '2000',
			'max_length'    => 5,
			'size'          => 6,
		),
		'cereus_ipam_import_header' => array(
			'friendly_name' => __('Import Settings', 'cereus_ipam'),
			'method'        => 'spacer',
		),
		'cereus_ipam_import_max_size' => array(
			'friendly_name' => __('Max Import File Size (MB)', 'cereus_ipam'),
			'description'   => __('Maximum file size allowed for CSV imports.', 'cereus_ipam'),
			'method'        => 'textbox',
			'default'       => '5',
			'max_length'    => 4,
			'size'          => 5,
		),
		'cereus_ipam_display_header' => array(
			'friendly_name' => __('Display Settings', 'cereus_ipam'),
			'method'        => 'spacer',
		),
		'cereus_ipam_resolve_dns' => array(
			'friendly_name' => __('Resolve DNS Names', 'cereus_ipam'),
			'description'   => __('Perform reverse DNS lookups when displaying IP addresses. May slow down large subnet views.', 'cereus_ipam'),
			'method'        => 'checkbox',
			'default'       => '',
		),
		'cereus_ipam_debug' => array(
			'friendly_name' => __('Debug Logging', 'cereus_ipam'),
			'description'   => __('Enable verbose debug logging to cacti.log.', 'cereus_ipam'),
			'method'        => 'checkbox',
			'default'       => '',
		),
		'cereus_ipam_threshold_header' => array(
			'friendly_name' => __('Threshold Alerts (Professional+)', 'cereus_ipam'),
			'method'        => 'spacer',
			'collapsible'   => 'true',
		),
		'cereus_ipam_threshold_enabled' => array(
			'friendly_name' => __('Enable Threshold Alerts', 'cereus_ipam'),
			'description'   => __('Send email alerts when subnet utilization exceeds the configured threshold.', 'cereus_ipam'),
			'method'        => 'checkbox',
			'default'       => '',
		),
		'cereus_ipam_threshold_emails' => array(
			'friendly_name' => __('Alert Recipients', 'cereus_ipam'),
			'description'   => __('Comma-separated email addresses for threshold alerts.', 'cereus_ipam'),
			'method'        => 'textbox',
			'default'       => '',
			'max_length'    => 512,
			'size'          => 60,
		),
		'cereus_ipam_threshold_notify_list' => $has_notify_lists ? array(
			'friendly_name' => __('Threshold Notification List', 'cereus_ipam'),
			'description'   => __('Select a Cacti notification list to receive threshold alerts (additive to manual recipients above).', 'cereus_ipam'),
			'method'        => 'drop_sql',
			'sql'           => "SELECT id, name FROM plugin_notification_lists ORDER BY name",
			'none_value'    => 'None',
			'default'       => '0',
		) : array(
			'friendly_name' => __('Threshold Notification List', 'cereus_ipam'),
			'description'   => __('Requires the Thold plugin to be installed for notification list support.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'array'         => array(0 => __('N/A - Thold not installed', 'cereus_ipam')),
			'default'       => '0',
		),
		'cereus_ipam_threshold_cooldown' => array(
			'friendly_name' => __('Alert Cooldown (seconds)', 'cereus_ipam'),
			'description'   => __('Minimum time between repeated alerts for the same subnet. Default: 86400 (24 hours).', 'cereus_ipam'),
			'method'        => 'textbox',
			'default'       => '86400',
			'max_length'    => 8,
			'size'          => 8,
		),
		'cereus_ipam_conflict_header' => array(
			'friendly_name' => __('Conflict Detection (Professional+)', 'cereus_ipam'),
			'method'        => 'spacer',
			'collapsible'   => 'true',
		),
		'cereus_ipam_conflict_alerts_enabled' => array(
			'friendly_name' => __('Enable Conflict Alerts', 'cereus_ipam'),
			'description'   => __('Send email alerts when new IP conflicts are detected after a network scan.', 'cereus_ipam'),
			'method'        => 'checkbox',
			'default'       => '',
		),
		'cereus_ipam_conflict_alert_types' => array(
			'friendly_name' => __('Alert on Conflict Types', 'cereus_ipam'),
			'description'   => __('Which conflict types should trigger email alerts. MAC Conflict = same IP with different MAC; Rogue = IP alive but not in IPAM; Stale = IP in IPAM but not responding.', 'cereus_ipam'),
			'method'        => 'drop_multi',
			'default'       => 'mac_conflict',
			'array'         => array(
				'mac_conflict' => __('MAC Conflict', 'cereus_ipam'),
				'rogue'        => __('Rogue/Unmanaged', 'cereus_ipam'),
				'stale'        => __('Stale', 'cereus_ipam'),
			),
		),
		'cereus_ipam_conflict_alert_emails' => array(
			'friendly_name' => __('Conflict Alert Recipients', 'cereus_ipam'),
			'description'   => __('Comma-separated email addresses for conflict alerts.', 'cereus_ipam'),
			'method'        => 'textbox',
			'default'       => '',
			'max_length'    => 512,
			'size'          => 60,
		),
		'cereus_ipam_conflict_notify_list' => $has_notify_lists ? array(
			'friendly_name' => __('Conflict Notification List', 'cereus_ipam'),
			'description'   => __('Select a Cacti notification list to receive conflict alerts (additive to manual recipients above).', 'cereus_ipam'),
			'method'        => 'drop_sql',
			'sql'           => "SELECT id, name FROM plugin_notification_lists ORDER BY name",
			'none_value'    => 'None',
			'default'       => '0',
		) : array(
			'friendly_name' => __('Conflict Notification List', 'cereus_ipam'),
			'description'   => __('Requires the Thold plugin to be installed for notification list support.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'array'         => array(0 => __('N/A - Thold not installed', 'cereus_ipam')),
			'default'       => '0',
		),
		'cereus_ipam_report_header' => array(
			'friendly_name' => __('Scheduled Report Emails (Professional+)', 'cereus_ipam'),
			'method'        => 'spacer',
			'collapsible'   => 'true',
		),
		'cereus_ipam_report_schedule_enabled' => array(
			'friendly_name' => __('Enable Scheduled Reports', 'cereus_ipam'),
			'description'   => __('Automatically generate and email IPAM reports on a schedule.', 'cereus_ipam'),
			'method'        => 'checkbox',
			'default'       => '',
		),
		'cereus_ipam_report_frequency' => array(
			'friendly_name' => __('Report Frequency', 'cereus_ipam'),
			'description'   => __('How often to send scheduled report emails.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'default'       => 'weekly',
			'array'         => array(
				'daily'   => __('Daily', 'cereus_ipam'),
				'weekly'  => __('Weekly', 'cereus_ipam'),
				'monthly' => __('Monthly', 'cereus_ipam'),
			),
		),
		'cereus_ipam_report_recipients' => array(
			'friendly_name' => __('Report Recipients', 'cereus_ipam'),
			'description'   => __('Comma-separated email addresses to receive scheduled reports.', 'cereus_ipam'),
			'method'        => 'textbox',
			'default'       => '',
			'max_length'    => 512,
			'size'          => 60,
		),
		'cereus_ipam_report_notify_list' => $has_notify_lists ? array(
			'friendly_name' => __('Report Notification List', 'cereus_ipam'),
			'description'   => __('Select a Cacti notification list to receive scheduled reports (additive to manual recipients above).', 'cereus_ipam'),
			'method'        => 'drop_sql',
			'sql'           => "SELECT id, name FROM plugin_notification_lists ORDER BY name",
			'none_value'    => 'None',
			'default'       => '0',
		) : array(
			'friendly_name' => __('Report Notification List', 'cereus_ipam'),
			'description'   => __('Requires the Thold plugin to be installed for notification list support.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'array'         => array(0 => __('N/A - Thold not installed', 'cereus_ipam')),
			'default'       => '0',
		),
		'cereus_ipam_report_inc_utilization' => array(
			'friendly_name' => __('Include Utilization Report', 'cereus_ipam'),
			'description'   => __('Include subnet utilization data in the scheduled report.', 'cereus_ipam'),
			'method'        => 'checkbox',
			'default'       => 'on',
		),
		'cereus_ipam_report_inc_states' => array(
			'friendly_name' => __('Include State Summary', 'cereus_ipam'),
			'description'   => __('Include address state summary in the scheduled report.', 'cereus_ipam'),
			'method'        => 'checkbox',
			'default'       => 'on',
		),
		'cereus_ipam_report_inc_stale' => array(
			'friendly_name' => __('Include Stale Addresses', 'cereus_ipam'),
			'description'   => __('Include stale address listing in the scheduled report.', 'cereus_ipam'),
			'method'        => 'checkbox',
			'default'       => '',
		),
		'cereus_ipam_report_stale_days' => array(
			'friendly_name' => __('Stale Threshold (days)', 'cereus_ipam'),
			'description'   => __('Addresses not seen in this many days are considered stale for report purposes.', 'cereus_ipam'),
			'method'        => 'textbox',
			'default'       => '90',
			'max_length'    => 5,
			'size'          => 5,
		),
		'cereus_ipam_webhook_header' => array(
			'friendly_name' => __('Webhook Callbacks (Enterprise)', 'cereus_ipam'),
			'method'        => 'spacer',
			'collapsible'   => 'true',
		),
		'cereus_ipam_webhook_enabled' => array(
			'friendly_name' => __('Enable Webhooks', 'cereus_ipam'),
			'description'   => __('Send webhook POST requests when IPAM objects are created, updated, or deleted.', 'cereus_ipam'),
			'method'        => 'checkbox',
			'default'       => '',
		),
		'cereus_ipam_webhook_urls' => array(
			'friendly_name' => __('Webhook URLs', 'cereus_ipam'),
			'description'   => __('One webhook URL per line. Each URL will receive a JSON POST for every IPAM change event.', 'cereus_ipam'),
			'method'        => 'textarea',
			'default'       => '',
			'max_length'    => 2048,
			'textarea_rows' => 4,
			'textarea_cols' => 60,
		),
		'cereus_ipam_webhook_test_url' => array(
			'friendly_name' => __('Test Webhook URL', 'cereus_ipam'),
			'description'   => __('Enter a URL and click the Test button to send a test payload and verify webhook connectivity.', 'cereus_ipam'),
			'method'        => 'textbox',
			'default'       => '',
			'max_length'    => 512,
			'size'          => 60,
		),
	);
}
