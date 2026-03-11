<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2024-2026 Urban-Software.de / Thomas Urban               |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 +-------------------------------------------------------------------------+
 | Cereus IPAM - Dashboard / Summary Widget Page                           |
 +-------------------------------------------------------------------------+
*/

chdir('../../');
include('./include/auth.php');
include_once('./plugins/cereus_ipam/includes/constants.php');
include_once('./plugins/cereus_ipam/lib/license_check.php');
include_once('./plugins/cereus_ipam/lib/validation.php');
include_once('./plugins/cereus_ipam/lib/ip_utils.php');
include_once('./plugins/cereus_ipam/lib/functions.php');
include_once('./plugins/cereus_ipam/lib/changelog.php');

top_header();
cereus_ipam_dashboard();
bottom_footer();

/* ==================== Dashboard Render ==================== */

function cereus_ipam_dashboard() {
	global $config;

	cereus_ipam_dashboard_summary();
	cereus_ipam_dashboard_top_utilized();
	cereus_ipam_dashboard_address_states();
	cereus_ipam_dashboard_recent_changes();

	/* Professional+: Active Scans widget */
	if (cereus_ipam_license_has_scanning()) {
		cereus_ipam_dashboard_active_scans();
	}

	/* Professional+: Active Conflicts widget */
	if (cereus_ipam_license_has_scanning()) {
		include_once($config['base_path'] . '/plugins/cereus_ipam/lib/conflicts.php');
		cereus_ipam_dashboard_conflicts();
	}

	/* Enterprise: Capacity Forecast Warnings */
	if (cereus_ipam_license_at_least('enterprise')) {
		include_once($config['base_path'] . '/plugins/cereus_ipam/lib/forecast.php');
		cereus_ipam_dashboard_forecast_warnings();
	}

	/* Enterprise: Active Maintenance Windows */
	if (cereus_ipam_license_has_maintenance()) {
		cereus_ipam_dashboard_maintenance_windows();
	}
}

/* ==================== Widget 1: Summary Statistics ==================== */

function cereus_ipam_dashboard_summary() {
	$total_sections  = (int) db_fetch_cell("SELECT COUNT(*) FROM plugin_cereus_ipam_sections");
	$total_subnets   = (int) db_fetch_cell("SELECT COUNT(*) FROM plugin_cereus_ipam_subnets");
	$total_addresses = (int) db_fetch_cell("SELECT COUNT(*) FROM plugin_cereus_ipam_addresses");
	$ipv4_subnets    = (int) db_fetch_cell("SELECT COUNT(*) FROM plugin_cereus_ipam_subnets WHERE subnet NOT LIKE '%:%'");
	$ipv6_subnets    = (int) db_fetch_cell("SELECT COUNT(*) FROM plugin_cereus_ipam_subnets WHERE subnet LIKE '%:%'");
	$active_addr     = (int) db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_addresses WHERE state = ?", array('active'));
	$reserved_addr   = (int) db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_addresses WHERE state = ?", array('reserved'));
	$available_addr  = (int) db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_addresses WHERE state = ?", array('available'));
	$total_vlans     = (int) db_fetch_cell("SELECT COUNT(*) FROM plugin_cereus_ipam_vlans");
	$total_vrfs      = (int) db_fetch_cell("SELECT COUNT(*) FROM plugin_cereus_ipam_vrfs");
	$license_tier    = ucfirst(cereus_ipam_license_tier());

	$stats = array(
		array('value' => $total_sections,  'label' => __('Sections', 'cereus_ipam'),          'color' => '#2c3e50'),
		array('value' => $total_subnets,   'label' => __('Total Subnets', 'cereus_ipam'),     'color' => '#2c3e50'),
		array('value' => $total_addresses, 'label' => __('Total Addresses', 'cereus_ipam'),   'color' => '#2c3e50'),
		array('value' => $ipv4_subnets,    'label' => __('IPv4 Subnets', 'cereus_ipam'),      'color' => '#2980b9'),
		array('value' => $ipv6_subnets,    'label' => __('IPv6 Subnets', 'cereus_ipam'),      'color' => '#8e44ad'),
		array('value' => $active_addr,     'label' => __('Active Addresses', 'cereus_ipam'),  'color' => '#27ae60'),
		array('value' => $reserved_addr,   'label' => __('Reserved Addresses', 'cereus_ipam'), 'color' => '#2980b9'),
		array('value' => $available_addr,  'label' => __('Available Addresses', 'cereus_ipam'), 'color' => '#7f8c8d'),
		array('value' => $total_vlans,     'label' => __('VLANs', 'cereus_ipam'),             'color' => '#e67e22'),
		array('value' => $total_vrfs,      'label' => __('VRFs', 'cereus_ipam'),              'color' => '#e67e22'),
		array('value' => $license_tier,    'label' => __('License Tier', 'cereus_ipam'),      'color' => '#16a085'),
	);

	html_start_box(__('IPAM Overview', 'cereus_ipam'), '100%', '', '3', 'center', '');

	print '<tr class="even"><td style="padding:15px;">';
	print '<table class="filterTable" style="width:100%;">';

	/* Render in rows of 4 */
	$per_row = 4;
	$count   = cacti_sizeof($stats);

	for ($i = 0; $i < $count; $i++) {
		if ($i % $per_row === 0) {
			print '<tr>';
		}

		$val   = $stats[$i]['value'];
		$label = $stats[$i]['label'];
		$color = $stats[$i]['color'];

		print '<td style="text-align:center; padding:10px 15px; width:25%;">';
		print '<div style="font-size:24px; font-weight:bold; color:' . html_escape($color) . ';">' . html_escape($val) . '</div>';
		print '<div style="font-size:12px; color:#7f8c8d;">' . html_escape($label) . '</div>';
		print '</td>';

		if (($i + 1) % $per_row === 0 || ($i + 1) === $count) {
			/* Fill remaining cells if this is the last row */
			if (($i + 1) === $count && ($i + 1) % $per_row !== 0) {
				$remaining = $per_row - (($i + 1) % $per_row);
				for ($j = 0; $j < $remaining; $j++) {
					print '<td>&nbsp;</td>';
				}
			}
			print '</tr>';
		}
	}

	print '</table>';
	print '</td></tr>';

	html_end_box();
}

/* ==================== Widget 2: Top 10 Most Utilized Subnets ==================== */

function cereus_ipam_dashboard_top_utilized() {
	global $config;

	$subnets = db_fetch_assoc(
		"SELECT s.id, s.subnet, s.mask, s.description, s.section_id, sec.name AS section_name
		FROM plugin_cereus_ipam_subnets s
		LEFT JOIN plugin_cereus_ipam_sections sec ON sec.id = s.section_id
		ORDER BY s.subnet"
	);

	if (!cacti_sizeof($subnets)) {
		html_start_box(__('Top 10 Most Utilized Subnets', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr class="even"><td>' . __('No subnets found.', 'cereus_ipam') . '</td></tr>';
		html_end_box();
		return;
	}

	/* Compute utilization for each subnet */
	$util_data = array();
	foreach ($subnets as $s) {
		$util = cereus_ipam_subnet_utilization($s['id']);
		$s['used']  = $util['used'];
		$s['total'] = $util['total'];
		$s['pct']   = $util['pct'];
		$util_data[] = $s;
	}

	/* Sort by pct descending */
	usort($util_data, function ($a, $b) {
		if ($b['pct'] == $a['pct']) {
			return 0;
		}
		return ($b['pct'] > $a['pct']) ? 1 : -1;
	});

	/* Take top 10 */
	$top10 = array_slice($util_data, 0, 10);

	html_start_box(__('Top 10 Most Utilized Subnets', 'cereus_ipam'), '100%', '', '3', 'center', '');

	$display_text = array(
		array('display' => __('Subnet', 'cereus_ipam'),      'align' => 'left'),
		array('display' => __('Description', 'cereus_ipam'), 'align' => 'left'),
		array('display' => __('Section', 'cereus_ipam'),     'align' => 'left'),
		array('display' => __('Used / Total', 'cereus_ipam'), 'align' => 'right'),
		array('display' => __('Utilization', 'cereus_ipam'), 'align' => 'left'),
	);

	html_header($display_text);

	$plugin_url = $config['url_path'] . 'plugins/cereus_ipam/';

	foreach ($top10 as $row) {
		$cidr = html_escape($row['subnet'] . '/' . $row['mask']);
		form_alternate_row();
		print '<td><a class="linkEditMain" href="' . html_escape($plugin_url . 'cereus_ipam_addresses.php?subnet_id=' . $row['id']) . '">' . $cidr . '</a>';
		print ' <a href="' . html_escape($plugin_url . 'cereus_ipam_addresses.php?action=visual&subnet_id=' . $row['id']) . '" title="' . __esc('Visual Map', 'cereus_ipam') . '"><i class="fa fa-th" style="font-size:11px;color:#999;margin-left:4px;"></i></a></td>';
		print '<td>' . html_escape($row['description'] ?? '') . '</td>';
		print '<td>' . html_escape($row['section_name'] ?? '') . '</td>';
		print '<td style="text-align:right;"><a href="' . html_escape($plugin_url . 'cereus_ipam_addresses.php?subnet_id=' . $row['id']) . '">' . html_escape($row['used'] . ' / ' . $row['total']) . '</a></td>';
		print '<td><a href="' . html_escape($plugin_url . 'cereus_ipam_addresses.php?action=visual&subnet_id=' . $row['id']) . '">' . cereus_ipam_utilization_bar($row['pct']) . '</a></td>';
		form_end_row();
	}

	html_end_box();
}

/* ==================== Widget 3: Address State Distribution ==================== */

function cereus_ipam_dashboard_address_states() {
	global $config;

	$states = db_fetch_assoc("SELECT state, COUNT(*) AS cnt FROM plugin_cereus_ipam_addresses GROUP BY state ORDER BY state");

	$state_colors = array(
		'active'    => '#4CAF50',
		'reserved'  => '#2196F3',
		'dhcp'      => '#FF9800',
		'offline'   => '#F44336',
		'available' => '#9E9E9E',
	);

	html_start_box(__('Address State Distribution', 'cereus_ipam'), '100%', '', '3', 'center', '');

	if (!cacti_sizeof($states)) {
		print '<tr class="even"><td>' . __('No address records found.', 'cereus_ipam') . '</td></tr>';
		html_end_box();
		return;
	}

	$display_text = array(
		array('display' => __('State', 'cereus_ipam'), 'align' => 'left'),
		array('display' => __('Count', 'cereus_ipam'), 'align' => 'right'),
	);

	html_header($display_text);

	$plugin_url = $config['url_path'] . 'plugins/cereus_ipam/';

	foreach ($states as $row) {
		$state = $row['state'];
		$count = (int) $row['cnt'];
		$color = isset($state_colors[$state]) ? $state_colors[$state] : '#9E9E9E';

		form_alternate_row();
		print '<td>';
		print '<span style="display:inline-block; width:12px; height:12px; border-radius:50%; background:' . html_escape($color) . '; margin-right:8px; vertical-align:middle;"></span>';
		print html_escape(ucfirst($state));
		print '</td>';
		print '<td style="text-align:right;"><a href="' . html_escape($plugin_url . 'cereus_ipam_search.php?query=' . urlencode($state)) . '">' . number_format_i18n($count) . '</a></td>';
		form_end_row();
	}

	html_end_box();
}

/* ==================== Widget 4: Recent Changes (last 24h) ==================== */

function cereus_ipam_dashboard_recent_changes() {
	global $config;

	$changes = db_fetch_assoc(
		"SELECT c.created, c.user_id, c.action, c.object_type, c.object_id, c.new_value
		FROM plugin_cereus_ipam_changelog c
		WHERE c.created >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
		ORDER BY c.created DESC
		LIMIT 15"
	);

	html_start_box(__('Recent Changes (Last 24 Hours)', 'cereus_ipam'), '100%', '', '3', 'center', '');

	if (!cacti_sizeof($changes)) {
		print '<tr class="even"><td>' . __('No changes in the last 24 hours.', 'cereus_ipam') . '</td></tr>';
		html_end_box();
		return;
	}

	$display_text = array(
		array('display' => __('Time', 'cereus_ipam'),        'align' => 'left'),
		array('display' => __('User', 'cereus_ipam'),        'align' => 'left'),
		array('display' => __('Action', 'cereus_ipam'),      'align' => 'left'),
		array('display' => __('Object Type', 'cereus_ipam'), 'align' => 'left'),
		array('display' => __('Details', 'cereus_ipam'),     'align' => 'left'),
	);

	html_header($display_text);

	$plugin_url = $config['url_path'] . 'plugins/cereus_ipam/';

	foreach ($changes as $row) {
		$username = cereus_ipam_get_username($row['user_id']);

		/* Build a brief detail string with drill-down link */
		$detail_text = html_escape(ucfirst($row['object_type'])) . ' #' . html_escape($row['object_id']);
		$detail_link = '';

		if (!empty($row['new_value'])) {
			$nv = json_decode($row['new_value'], true);
			if (is_array($nv)) {
				if (isset($nv['subnet']) && isset($nv['mask'])) {
					$detail_text = html_escape($nv['subnet'] . '/' . $nv['mask']);
				} elseif (isset($nv['ip'])) {
					$detail_text = html_escape($nv['ip']);
				} elseif (isset($nv['name'])) {
					$detail_text = html_escape($nv['name']);
				}
			}
		}

		/* Build link to actual object */
		$oid = (int) $row['object_id'];
		switch ($row['object_type']) {
			case 'subnet':
				$detail_link = $plugin_url . 'cereus_ipam.php?action=edit&id=' . $oid;
				break;
			case 'address':
				$addr_sub = db_fetch_cell_prepared("SELECT subnet_id FROM plugin_cereus_ipam_addresses WHERE id = ?", array($oid));
				if ($addr_sub) {
					$detail_link = $plugin_url . 'cereus_ipam_addresses.php?action=edit&id=' . $oid . '&subnet_id=' . $addr_sub;
				}
				break;
			case 'section':
				$detail_link = $plugin_url . 'cereus_ipam.php?action=section_edit&id=' . $oid;
				break;
			case 'vlan':
				$detail_link = $plugin_url . 'cereus_ipam_vlans.php?action=edit&id=' . $oid;
				break;
			case 'vrf':
				$detail_link = $plugin_url . 'cereus_ipam_vrfs.php?action=edit&id=' . $oid;
				break;
		}

		$detail = !empty($detail_link)
			? '<a class="linkEditMain" href="' . html_escape($detail_link) . '">' . $detail_text . '</a>'
			: $detail_text;

		form_alternate_row();
		print '<td>' . html_escape($row['created']) . '</td>';
		print '<td>' . html_escape($username) . '</td>';
		print '<td>' . html_escape(ucfirst($row['action'])) . '</td>';
		print '<td>' . html_escape(ucfirst($row['object_type'])) . '</td>';
		print '<td>' . $detail . '</td>';
		form_end_row();
	}

	/* Link to full changelog */
	$plugin_url = $config['url_path'] . 'plugins/cereus_ipam/';
	print '<tr class="even"><td colspan="5" style="text-align:right; padding:8px;">';
	print '<a href="' . html_escape($plugin_url . 'cereus_ipam_changelog.php') . '">' . __('View full changelog', 'cereus_ipam') . ' &raquo;</a>';
	print '</td></tr>';

	html_end_box();
}

/* ==================== Widget 5: Active Scans (Professional+) ==================== */

function cereus_ipam_dashboard_active_scans() {
	global $config;

	$scans = db_fetch_assoc(
		"SELECT s.id, s.subnet, s.mask, s.description, s.last_scanned, s.scan_interval
		FROM plugin_cereus_ipam_subnets s
		WHERE s.scan_enabled = 1
		ORDER BY s.last_scanned DESC"
	);

	html_start_box(__('Active Scans', 'cereus_ipam'), '100%', '', '3', 'center', '');

	if (!cacti_sizeof($scans)) {
		print '<tr class="even"><td>' . __('No subnets have scanning enabled.', 'cereus_ipam') . '</td></tr>';
		html_end_box();
		return;
	}

	$display_text = array(
		array('display' => __('Subnet', 'cereus_ipam'),        'align' => 'left'),
		array('display' => __('Last Scanned', 'cereus_ipam'),  'align' => 'left'),
		array('display' => __('Scan Interval', 'cereus_ipam'), 'align' => 'right'),
		array('display' => __('Status', 'cereus_ipam'),        'align' => 'left'),
	);

	html_header($display_text);

	$plugin_url = $config['url_path'] . 'plugins/cereus_ipam/';

	foreach ($scans as $row) {
		$cidr = html_escape($row['subnet'] . '/' . $row['mask']);

		/* Determine scan status */
		if (empty($row['last_scanned'])) {
			$status       = __('Never Scanned', 'cereus_ipam');
			$status_color = '#FF9800';
		} else {
			$last_ts = strtotime($row['last_scanned']);
			$age     = time() - $last_ts;

			if ($age > ($row['scan_interval'] * 2)) {
				$status       = __('Overdue', 'cereus_ipam');
				$status_color = '#F44336';
			} else {
				$status       = __('OK', 'cereus_ipam');
				$status_color = '#4CAF50';
			}
		}

		/* Format interval */
		$interval_hours = round($row['scan_interval'] / 3600, 1);
		$interval_text  = $interval_hours . ' ' . __('hours', 'cereus_ipam');

		form_alternate_row();
		print '<td><a class="linkEditMain" href="' . html_escape($plugin_url . 'cereus_ipam_scan.php?subnet_id=' . $row['id']) . '">' . $cidr . '</a>';
		print (!empty($row['description']) ? ' - ' . html_escape($row['description']) : '') . '</td>';
		print '<td>' . html_escape($row['last_scanned'] ?? __('Never', 'cereus_ipam')) . '</td>';
		print '<td style="text-align:right;">' . html_escape($interval_text) . '</td>';
		print '<td><span style="color:' . html_escape($status_color) . '; font-weight:bold;">' . html_escape($status) . '</span></td>';
		form_end_row();
	}

	html_end_box();
}

/* ==================== Widget 6: Capacity Forecast Warnings (Enterprise) ==================== */

function cereus_ipam_dashboard_forecast_warnings() {
	global $config;

	$forecasts = cereus_ipam_forecast_summary();

	/* Take top 5 most urgent */
	$top5 = array_slice($forecasts, 0, 5);

	html_start_box(__('Capacity Forecast Warnings', 'cereus_ipam'), '100%', '', '3', 'center', '');

	if (!cacti_sizeof($top5)) {
		print '<tr class="even"><td>' . __('No subnets approaching exhaustion.', 'cereus_ipam') . '</td></tr>';
		html_end_box();
		return;
	}

	$display_text = array(
		array('display' => __('Subnet', 'cereus_ipam'),          'align' => 'left'),
		array('display' => __('Current Usage', 'cereus_ipam'),   'align' => 'right'),
		array('display' => __('Exhaustion Date', 'cereus_ipam'), 'align' => 'left'),
		array('display' => __('Days Remaining', 'cereus_ipam'),  'align' => 'right'),
		array('display' => __('Daily Growth', 'cereus_ipam'),    'align' => 'right'),
	);

	html_header($display_text);

	$plugin_url = $config['url_path'] . 'plugins/cereus_ipam/';

	foreach ($top5 as $row) {
		/* Color code urgency */
		if ($row['days_remaining'] <= 30) {
			$urgency_color = '#F44336';
		} elseif ($row['days_remaining'] <= 90) {
			$urgency_color = '#FF9800';
		} else {
			$urgency_color = '#2c3e50';
		}

		form_alternate_row();
		print '<td><a class="linkEditMain" href="' . html_escape($plugin_url . 'cereus_ipam.php?action=edit&id=' . $row['subnet_id']) . '">'
			. html_escape($row['subnet']) . '</a>'
			. (!empty($row['description']) ? ' - ' . html_escape($row['description']) : '') . '</td>';
		print '<td style="text-align:right;">' . html_escape($row['current_pct']) . '%</td>';
		print '<td>' . html_escape($row['exhaustion_date']) . '</td>';
		print '<td style="text-align:right; color:' . html_escape($urgency_color) . '; font-weight:bold;">' . html_escape($row['days_remaining']) . '</td>';
		print '<td style="text-align:right;">' . html_escape($row['daily_growth']) . '%/day</td>';
		form_end_row();
	}

	html_end_box();
}

/* ==================== Widget 7: Active Maintenance Windows (Enterprise) ==================== */

function cereus_ipam_dashboard_maintenance_windows() {
	$windows = db_fetch_assoc(
		"SELECT id, title, start_time, end_time, subnet_ids
		FROM plugin_cereus_ipam_maintenance
		WHERE start_time <= NOW() AND end_time >= NOW()
		ORDER BY end_time"
	);

	html_start_box(__('Active Maintenance Windows', 'cereus_ipam'), '100%', '', '3', 'center', '');

	if (!cacti_sizeof($windows)) {
		print '<tr class="even"><td>' . __('No active maintenance windows.', 'cereus_ipam') . '</td></tr>';
		html_end_box();
		return;
	}

	$display_text = array(
		array('display' => __('Title', 'cereus_ipam'),            'align' => 'left'),
		array('display' => __('Start', 'cereus_ipam'),            'align' => 'left'),
		array('display' => __('End', 'cereus_ipam'),              'align' => 'left'),
		array('display' => __('Subnets Affected', 'cereus_ipam'), 'align' => 'right'),
	);

	html_header($display_text);

	foreach ($windows as $row) {
		/* Count affected subnets */
		$subnet_count = 0;
		if (!empty($row['subnet_ids'])) {
			$ids = array_filter(explode(',', $row['subnet_ids']));
			$subnet_count = cacti_sizeof($ids);
		}

		form_alternate_row();
		print '<td>' . html_escape($row['title']) . '</td>';
		print '<td>' . html_escape($row['start_time']) . '</td>';
		print '<td>' . html_escape($row['end_time']) . '</td>';
		print '<td style="text-align:right;">' . html_escape($subnet_count) . '</td>';
		form_end_row();
	}

	html_end_box();
}

/* ==================== Widget 8: Active Conflicts (Professional+) ==================== */

function cereus_ipam_dashboard_conflicts() {
	global $config;

	$summary = cereus_ipam_conflict_summary();
	$plugin_url = $config['url_path'] . 'plugins/cereus_ipam/';

	html_start_box(
		__('Active Conflicts', 'cereus_ipam') . ' (' . $summary['total'] . ')',
		'100%', '', '3', 'center', ''
	);

	if ($summary['total'] == 0) {
		print '<tr class="even"><td style="padding:10px;">';
		print '<span style="color:#27ae60;"><i class="fa fa-check-circle"></i> ' . __('No active conflicts detected.', 'cereus_ipam') . '</span>';
		print '</td></tr>';
		html_end_box();
		return;
	}

	/* Summary by type */
	print '<tr class="even"><td style="padding:12px;">';
	print '<div style="display:flex;gap:30px;flex-wrap:wrap;">';

	$types = array('mac_conflict', 'rogue', 'stale');
	foreach ($types as $type) {
		$info = cereus_ipam_conflict_type_info($type);
		$cnt  = $summary[$type];
		print '<div style="text-align:center;">';
		print '<div style="font-size:28px;font-weight:bold;color:' . $info['color'] . ';">' . $cnt . '</div>';
		print '<div style="font-size:12px;color:#666;"><i class="fa ' . $info['icon'] . '"></i> ' . $info['label'] . '</div>';
		print '</div>';
	}

	print '</div>';
	print '</td></tr>';

	/* Show recent conflicts */
	$recent = cereus_ipam_get_active_conflicts(0, '', 10);
	if (cacti_sizeof($recent)) {
		$display_text = array(
			array('display' => __('IP', 'cereus_ipam'),      'align' => 'left'),
			array('display' => __('Type', 'cereus_ipam'),    'align' => 'left'),
			array('display' => __('Subnet', 'cereus_ipam'),  'align' => 'left'),
			array('display' => __('Detected', 'cereus_ipam'), 'align' => 'left'),
			array('display' => __('Details', 'cereus_ipam'), 'align' => 'left'),
		);
		html_header($display_text);

		foreach ($recent as $c) {
			$type_info = cereus_ipam_conflict_type_info($c['type']);
			$details = json_decode($c['details'], true);
			$detail_parts = array();
			if (is_array($details)) {
				foreach ($details as $k => $v) {
					if (!empty($v)) {
						$detail_parts[] = html_escape($k) . ': ' . html_escape($v);
					}
				}
			}

			form_alternate_row('conflict_' . $c['id']);
			$subnet_label = ($c['subnet'] && $c['mask']) ? $c['subnet'] . '/' . $c['mask'] : '';
			print '<td>' . html_escape($c['ip']) . '</td>';
			print '<td><span style="color:' . $type_info['color'] . ';"><i class="fa ' . $type_info['icon'] . '"></i> ' . $type_info['label'] . '</span></td>';
			print '<td><a href="' . html_escape($plugin_url . 'cereus_ipam_addresses.php?subnet_id=' . $c['subnet_id']) . '">' . html_escape($subnet_label) . '</a></td>';
			print '<td>' . html_escape($c['detected_at']) . '</td>';
			print '<td style="font-size:11px;">' . implode('; ', $detail_parts) . '</td>';
			form_end_row();
		}
	}

	html_end_box();
}
