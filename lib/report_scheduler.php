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
 | Cereus IPAM - Scheduled Report Email Delivery (Professional+)           |
 +-------------------------------------------------------------------------+
*/

/**
 * Check if a scheduled report is due and send it.
 * Called from cereus_ipam_poller_bottom().
 */
function cereus_ipam_check_scheduled_reports() {
	if (!cereus_ipam_license_at_least('professional')) {
		return;
	}

	$enabled = read_config_option('cereus_ipam_report_schedule_enabled');
	if ($enabled != 'on') {
		return;
	}

	$frequency  = read_config_option('cereus_ipam_report_frequency');
	$manual_recipients = trim(read_config_option('cereus_ipam_report_recipients'));
	$notify_list_id    = (int) read_config_option('cereus_ipam_report_notify_list');
	$recipients        = cereus_ipam_merge_notification_emails($manual_recipients, $notify_list_id);

	if (empty($recipients)) {
		return;
	}

	/* Check if report is due */
	$last_sent = read_config_option('cereus_ipam_report_last_sent');
	$now = time();

	if (!cereus_ipam_report_is_due($frequency, $last_sent, $now)) {
		return;
	}

	/* Determine which reports to send */
	$report_types = array();
	if (read_config_option('cereus_ipam_report_inc_utilization') == 'on') {
		$report_types[] = 'utilization';
	}
	if (read_config_option('cereus_ipam_report_inc_states') == 'on') {
		$report_types[] = 'states';
	}
	if (read_config_option('cereus_ipam_report_inc_stale') == 'on') {
		$report_types[] = 'stale';
	}

	if (empty($report_types)) {
		return;
	}

	/* Generate and send report */
	$success = cereus_ipam_send_scheduled_report($recipients, $report_types);

	if ($success) {
		set_config_option('cereus_ipam_report_last_sent', $now);
		cacti_log('CEREUS_IPAM: Scheduled report sent to ' . $recipients, false, 'CEREUS_IPAM');
	} else {
		cacti_log('CEREUS_IPAM WARNING: Failed to send scheduled report', false, 'CEREUS_IPAM');
	}
}

/**
 * Check if a report is due based on frequency and last sent time.
 */
function cereus_ipam_report_is_due($frequency, $last_sent, $now) {
	if (empty($last_sent)) {
		return true;
	}

	$last_sent = (int) $last_sent;
	$elapsed = $now - $last_sent;

	switch ($frequency) {
		case 'daily':
			return $elapsed >= 86400;
		case 'weekly':
			return $elapsed >= 604800;
		case 'monthly':
			return $elapsed >= 2592000; /* 30 days */
		default:
			return $elapsed >= 604800;
	}
}

/**
 * Generate report content and send via Cacti's mailer().
 */
function cereus_ipam_send_scheduled_report($recipients, $report_types) {
	global $config;

	include_once($config['base_path'] . '/lib/mailer.php');

	$email_list = array_map('trim', explode(',', $recipients));
	$email_list = array_filter($email_list);

	if (empty($email_list)) {
		return false;
	}

	/* Build HTML email body */
	$html = cereus_ipam_build_report_email($report_types);
	$text = strip_tags(str_replace(array('<br>', '</tr>', '</td>'), array("\n", "\n", "\t"), $html));

	/* Build CSV attachment */
	$csv_content = cereus_ipam_build_report_csv($report_types);
	$filename = 'ipam_report_' . date('Ymd') . '.csv';

	/* Prepare mailer */
	$from_email = read_config_option('settings_from_email');
	$from_name  = read_config_option('settings_from_name');

	if (empty($from_email)) {
		$from_email = 'cacti@' . php_uname('n');
	}
	if (empty($from_name)) {
		$from_name = 'Cacti';
	}

	$subject = __('Cereus IPAM Scheduled Report - %s', date('Y-m-d'), 'cereus_ipam');

	/* Save CSV to temp file for attachment */
	$tmp_csv = sys_get_temp_dir() . '/cereus_ipam_report_' . uniqid() . '.csv';
	file_put_contents($tmp_csv, $csv_content);

	$result = mailer(
		array($from_email, $from_name),
		$email_list,
		'',   /* CC */
		'',   /* BCC */
		array(array('attachment' => $tmp_csv, 'filename' => $filename, 'mime_type' => 'text/csv')),
		$subject,
		$html,
		$text
	);

	/* Cleanup temp file */
	@unlink($tmp_csv);

	return ($result == '');
}

/**
 * Build HTML email body with report data.
 */
function cereus_ipam_build_report_email($report_types) {
	$html = '<html><body style="font-family:Arial,sans-serif;font-size:12px;color:#333;">';
	$html .= '<h2 style="color:#1976D2;">' . __('Cereus IPAM Report', 'cereus_ipam') . '</h2>';
	$html .= '<p style="color:#666;font-size:11px;">' . __('Generated: %s', date('Y-m-d H:i:s'), 'cereus_ipam') . '</p>';

	foreach ($report_types as $type) {
		switch ($type) {
			case 'utilization':
				$html .= cereus_ipam_email_utilization();
				break;
			case 'states':
				$html .= cereus_ipam_email_states();
				break;
			case 'stale':
				$html .= cereus_ipam_email_stale();
				break;
		}
	}

	$html .= '<hr style="border:none;border-top:1px solid #ddd;margin:20px 0;">';
	$html .= '<p style="font-size:10px;color:#999;">' . __('Cereus IPAM by Urban-Software.de', 'cereus_ipam') . '</p>';
	$html .= '</body></html>';

	return $html;
}

/**
 * Build combined CSV attachment for all selected report types.
 */
function cereus_ipam_build_report_csv($report_types) {
	$fh = fopen('php://temp', 'r+');

	foreach ($report_types as $type) {
		switch ($type) {
			case 'utilization':
				fputcsv($fh, array('--- Subnet Utilization ---'));
				fputcsv($fh, array('Subnet/CIDR', 'Section', 'Description', 'Used', 'Total', 'Utilization %', 'Status'));
				cereus_ipam_csv_utilization_data($fh);
				fputcsv($fh, array(''));
				break;
			case 'states':
				fputcsv($fh, array('--- Address State Summary ---'));
				fputcsv($fh, array('Subnet', 'Active', 'Reserved', 'DHCP', 'Offline', 'Available'));
				cereus_ipam_csv_states_data($fh);
				fputcsv($fh, array(''));
				break;
			case 'stale':
				$stale_days = (int) read_config_option('cereus_ipam_report_stale_days');
				if ($stale_days <= 0) {
					$stale_days = 90;
				}
				fputcsv($fh, array('--- Stale Addresses (>' . $stale_days . ' days) ---'));
				fputcsv($fh, array('IP', 'Hostname', 'Subnet', 'State', 'Last Seen', 'Owner'));
				cereus_ipam_csv_stale_data($fh, $stale_days);
				fputcsv($fh, array(''));
				break;
		}
	}

	rewind($fh);
	$content = stream_get_contents($fh);
	fclose($fh);

	return $content;
}

/* ==================== Email Report Sections ==================== */

function cereus_ipam_email_utilization() {
	$subnets = db_fetch_assoc(
		"SELECT s.*, sec.name AS section_name
		FROM plugin_cereus_ipam_subnets s
		LEFT JOIN plugin_cereus_ipam_sections sec ON sec.id = s.section_id
		ORDER BY s.subnet, s.mask"
	);

	$data = array();
	if (cacti_sizeof($subnets)) {
		foreach ($subnets as $s) {
			$util = cereus_ipam_subnet_utilization($s['id']);
			$pct = $util['pct'];
			if ($pct >= 90) {
				$status = 'Critical';
				$color = '#F44336';
			} elseif ($pct >= 75) {
				$status = 'Warning';
				$color = '#FF9800';
			} else {
				$status = 'OK';
				$color = '#4CAF50';
			}

			$data[] = array(
				'cidr'   => $s['subnet'] . '/' . $s['mask'],
				'section' => $s['section_name'] ?? '',
				'used'   => $util['used'],
				'total'  => $util['total'],
				'pct'    => $pct,
				'status' => $status,
				'color'  => $color,
			);
		}
	}

	usort($data, function ($a, $b) {
		return $b['pct'] <=> $a['pct'];
	});

	$html = '<h3 style="margin-top:20px;">' . __('Subnet Utilization', 'cereus_ipam') . '</h3>';
	$html .= '<table style="width:100%;border-collapse:collapse;margin-bottom:15px;">';
	$html .= '<tr style="background:#f0f0f0;">';
	$html .= '<th style="border:1px solid #ddd;padding:5px;text-align:left;">' . __('Subnet', 'cereus_ipam') . '</th>';
	$html .= '<th style="border:1px solid #ddd;padding:5px;text-align:left;">' . __('Section', 'cereus_ipam') . '</th>';
	$html .= '<th style="border:1px solid #ddd;padding:5px;text-align:right;">' . __('Used/Total', 'cereus_ipam') . '</th>';
	$html .= '<th style="border:1px solid #ddd;padding:5px;text-align:right;">' . __('Utilization', 'cereus_ipam') . '</th>';
	$html .= '<th style="border:1px solid #ddd;padding:5px;text-align:center;">' . __('Status', 'cereus_ipam') . '</th>';
	$html .= '</tr>';

	foreach ($data as $d) {
		$html .= '<tr>';
		$html .= '<td style="border:1px solid #ddd;padding:4px;">' . html_escape($d['cidr']) . '</td>';
		$html .= '<td style="border:1px solid #ddd;padding:4px;">' . html_escape($d['section']) . '</td>';
		$html .= '<td style="border:1px solid #ddd;padding:4px;text-align:right;">' . $d['used'] . '/' . $d['total'] . '</td>';
		$html .= '<td style="border:1px solid #ddd;padding:4px;text-align:right;">' . $d['pct'] . '%</td>';
		$html .= '<td style="border:1px solid #ddd;padding:4px;text-align:center;color:' . $d['color'] . ';font-weight:bold;">' . $d['status'] . '</td>';
		$html .= '</tr>';
	}

	$html .= '</table>';

	return $html;
}

function cereus_ipam_email_states() {
	$state_data = db_fetch_assoc("SELECT subnet_id, state, COUNT(*) AS cnt
		FROM plugin_cereus_ipam_addresses
		GROUP BY subnet_id, state");

	$state_map = array();
	if (cacti_sizeof($state_data)) {
		foreach ($state_data as $sd) {
			$state_map[$sd['subnet_id']][$sd['state']] = (int) $sd['cnt'];
		}
	}

	$subnets = db_fetch_assoc(
		"SELECT s.id, s.subnet, s.mask
		FROM plugin_cereus_ipam_subnets s
		ORDER BY s.subnet, s.mask"
	);

	$states = array('active', 'reserved', 'dhcp', 'offline', 'available');
	$totals = array_fill_keys($states, 0);

	$html = '<h3 style="margin-top:20px;">' . __('Address State Summary', 'cereus_ipam') . '</h3>';
	$html .= '<table style="width:100%;border-collapse:collapse;margin-bottom:15px;">';
	$html .= '<tr style="background:#f0f0f0;">';
	$html .= '<th style="border:1px solid #ddd;padding:5px;text-align:left;">' . __('Subnet', 'cereus_ipam') . '</th>';
	foreach ($states as $st) {
		$html .= '<th style="border:1px solid #ddd;padding:5px;text-align:right;">' . ucfirst($st) . '</th>';
	}
	$html .= '</tr>';

	if (cacti_sizeof($subnets)) foreach ($subnets as $s) {
		$html .= '<tr>';
		$html .= '<td style="border:1px solid #ddd;padding:4px;">' . html_escape($s['subnet'] . '/' . $s['mask']) . '</td>';
		foreach ($states as $st) {
			$cnt = $state_map[$s['id']][$st] ?? 0;
			$totals[$st] += $cnt;
			$html .= '<td style="border:1px solid #ddd;padding:4px;text-align:right;">' . $cnt . '</td>';
		}
		$html .= '</tr>';
	}

	$html .= '<tr style="font-weight:bold;">';
	$html .= '<td style="border:1px solid #ddd;padding:4px;">' . __('Total', 'cereus_ipam') . '</td>';
	foreach ($states as $st) {
		$html .= '<td style="border:1px solid #ddd;padding:4px;text-align:right;">' . $totals[$st] . '</td>';
	}
	$html .= '</tr>';
	$html .= '</table>';

	return $html;
}

function cereus_ipam_email_stale() {
	$stale_days = (int) read_config_option('cereus_ipam_report_stale_days');
	if ($stale_days <= 0) {
		$stale_days = 90;
	}
	$cutoff = date('Y-m-d H:i:s', strtotime("-{$stale_days} days"));

	$addresses = db_fetch_assoc_prepared(
		"SELECT a.ip, a.hostname, a.state, a.last_seen, s.subnet, s.mask
		FROM plugin_cereus_ipam_addresses a
		JOIN plugin_cereus_ipam_subnets s ON s.id = a.subnet_id
		WHERE a.state IN ('active', 'offline')
			AND (a.last_seen < ? OR a.last_seen IS NULL)
		ORDER BY a.last_seen ASC
		LIMIT 50",
		array($cutoff)
	);

	$total_stale = db_fetch_cell_prepared(
		"SELECT COUNT(*) FROM plugin_cereus_ipam_addresses
		WHERE state IN ('active', 'offline')
			AND (last_seen < ? OR last_seen IS NULL)",
		array($cutoff)
	);

	$html = '<h3 style="margin-top:20px;">' . __('Stale Addresses', 'cereus_ipam') . ' (' . __('not seen in %d days', $stale_days, 'cereus_ipam') . ')</h3>';
	$html .= '<p style="font-size:11px;color:#666;">' . __('Total stale: %d', $total_stale, 'cereus_ipam');
	if ($total_stale > 50) {
		$html .= ' (' . __('showing first 50', 'cereus_ipam') . ')';
	}
	$html .= '</p>';

	$html .= '<table style="width:100%;border-collapse:collapse;margin-bottom:15px;">';
	$html .= '<tr style="background:#f0f0f0;">';
	$html .= '<th style="border:1px solid #ddd;padding:5px;text-align:left;">' . __('IP', 'cereus_ipam') . '</th>';
	$html .= '<th style="border:1px solid #ddd;padding:5px;text-align:left;">' . __('Hostname', 'cereus_ipam') . '</th>';
	$html .= '<th style="border:1px solid #ddd;padding:5px;text-align:left;">' . __('Subnet', 'cereus_ipam') . '</th>';
	$html .= '<th style="border:1px solid #ddd;padding:5px;text-align:left;">' . __('Last Seen', 'cereus_ipam') . '</th>';
	$html .= '</tr>';

	if (cacti_sizeof($addresses)) foreach ($addresses as $a) {
		$html .= '<tr>';
		$html .= '<td style="border:1px solid #ddd;padding:4px;">' . html_escape($a['ip']) . '</td>';
		$html .= '<td style="border:1px solid #ddd;padding:4px;">' . html_escape($a['hostname'] ?? '') . '</td>';
		$html .= '<td style="border:1px solid #ddd;padding:4px;">' . html_escape($a['subnet'] . '/' . $a['mask']) . '</td>';
		$html .= '<td style="border:1px solid #ddd;padding:4px;">' . ($a['last_seen'] ?? __('Never', 'cereus_ipam')) . '</td>';
		$html .= '</tr>';
	}

	$html .= '</table>';

	return $html;
}

/* ==================== CSV Data for Attachment ==================== */

function cereus_ipam_csv_utilization_data($fh) {
	$subnets = db_fetch_assoc(
		"SELECT s.*, sec.name AS section_name
		FROM plugin_cereus_ipam_subnets s
		LEFT JOIN plugin_cereus_ipam_sections sec ON sec.id = s.section_id
		ORDER BY s.subnet, s.mask"
	);

	if (cacti_sizeof($subnets)) foreach ($subnets as $s) {
		$util = cereus_ipam_subnet_utilization($s['id']);
		$pct = $util['pct'];
		$status = ($pct >= 90) ? 'Critical' : (($pct >= 75) ? 'Warning' : 'OK');

		fputcsv($fh, array(
			$s['subnet'] . '/' . $s['mask'],
			$s['section_name'] ?? '',
			$s['description'] ?? '',
			$util['used'],
			$util['total'],
			$pct,
			$status,
		));
	}
}

function cereus_ipam_csv_states_data($fh) {
	$state_data = db_fetch_assoc("SELECT subnet_id, state, COUNT(*) AS cnt
		FROM plugin_cereus_ipam_addresses
		GROUP BY subnet_id, state");

	$state_map = array();
	if (cacti_sizeof($state_data)) {
		foreach ($state_data as $sd) {
			$state_map[$sd['subnet_id']][$sd['state']] = (int) $sd['cnt'];
		}
	}

	$subnets = db_fetch_assoc(
		"SELECT id, subnet, mask FROM plugin_cereus_ipam_subnets ORDER BY subnet, mask"
	);

	$states = array('active', 'reserved', 'dhcp', 'offline', 'available');

	if (cacti_sizeof($subnets)) foreach ($subnets as $s) {
		$row = array($s['subnet'] . '/' . $s['mask']);
		foreach ($states as $st) {
			$row[] = $state_map[$s['id']][$st] ?? 0;
		}
		fputcsv($fh, $row);
	}
}

function cereus_ipam_csv_stale_data($fh, $stale_days) {
	$cutoff = date('Y-m-d H:i:s', strtotime("-{$stale_days} days"));

	$addresses = db_fetch_assoc_prepared(
		"SELECT a.ip, a.hostname, a.state, a.last_seen, a.owner, s.subnet, s.mask
		FROM plugin_cereus_ipam_addresses a
		JOIN plugin_cereus_ipam_subnets s ON s.id = a.subnet_id
		WHERE a.state IN ('active', 'offline')
			AND (a.last_seen < ? OR a.last_seen IS NULL)
		ORDER BY a.last_seen ASC, a.ip",
		array($cutoff)
	);

	if (cacti_sizeof($addresses)) foreach ($addresses as $a) {
		fputcsv($fh, array(
			$a['ip'],
			$a['hostname'] ?? '',
			$a['subnet'] . '/' . $a['mask'],
			ucfirst($a['state']),
			$a['last_seen'] ?? 'Never',
			$a['owner'] ?? '',
		));
	}
}
