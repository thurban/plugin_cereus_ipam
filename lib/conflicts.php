<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2024-2026 Urban-Software.de / Thomas Urban               |
 +-------------------------------------------------------------------------+
 | Cereus IPAM - IP Conflict Detection Engine (Professional+)              |
 +-------------------------------------------------------------------------+
*/

/**
 * Run conflict detection for a subnet after a scan.
 * Compares scan results against IPAM address records.
 *
 * Detects three conflict types:
 *   mac_conflict — Same IP seen with different MAC than IPAM record
 *   rogue        — IP alive on network but not in IPAM
 *   stale        — IP in IPAM as active but not alive on scan
 *
 * @param int $subnet_id Subnet ID
 * @return array Summary of detected conflicts
 */
function cereus_ipam_detect_conflicts($subnet_id) {
	$subnet_id = (int) $subnet_id;
	$now = date('Y-m-d H:i:s');
	$new_conflicts = array();

	/* Get the latest scan results for this subnet */
	$scan_results = db_fetch_assoc_prepared(
		"SELECT ip, is_alive, mac_address, hostname
		FROM plugin_cereus_ipam_scan_results
		WHERE subnet_id = ?
		AND scanned_at = (SELECT MAX(scanned_at) FROM plugin_cereus_ipam_scan_results WHERE subnet_id = ?)
		ORDER BY ip",
		array($subnet_id, $subnet_id)
	);

	if (!cacti_sizeof($scan_results)) {
		return $new_conflicts;
	}

	/* Build scan result maps */
	$scan_alive = array();  /* ip => mac */
	foreach ($scan_results as $sr) {
		if ($sr['is_alive']) {
			$scan_alive[$sr['ip']] = $sr['mac_address'] ?? '';
		}
	}

	/* Get all IPAM address records for this subnet */
	$ipam_addresses = db_fetch_assoc_prepared(
		"SELECT id, ip, mac_address, state, hostname
		FROM plugin_cereus_ipam_addresses
		WHERE subnet_id = ?",
		array($subnet_id)
	);

	$ipam_by_ip = array();
	foreach ($ipam_addresses as $addr) {
		$ipam_by_ip[$addr['ip']] = $addr;
	}

	/* Detection 1: MAC conflicts — IP in IPAM with different MAC than scan */
	foreach ($scan_alive as $ip => $scan_mac) {
		if (empty($scan_mac)) {
			continue;
		}

		if (isset($ipam_by_ip[$ip]) && !empty($ipam_by_ip[$ip]['mac_address'])) {
			$ipam_mac = strtoupper(trim($ipam_by_ip[$ip]['mac_address']));
			$s_mac    = strtoupper(trim($scan_mac));

			if ($ipam_mac !== $s_mac) {
				$details = json_encode(array(
					'ipam_mac'    => $ipam_mac,
					'scan_mac'    => $s_mac,
					'ipam_host'   => $ipam_by_ip[$ip]['hostname'] ?? '',
					'ipam_state'  => $ipam_by_ip[$ip]['state'],
				));
				$new_conflicts[] = cereus_ipam_record_conflict($subnet_id, $ip, 'mac_conflict', $details, $now);
			}
		}
	}

	/* Detection 2: Rogue IPs — alive on scan but not in IPAM */
	foreach ($scan_alive as $ip => $scan_mac) {
		if (!isset($ipam_by_ip[$ip])) {
			$hostname = @gethostbyaddr($ip);
			$details = json_encode(array(
				'scan_mac'  => $scan_mac,
				'hostname'  => ($hostname !== $ip && $hostname !== false) ? $hostname : '',
			));
			$new_conflicts[] = cereus_ipam_record_conflict($subnet_id, $ip, 'rogue', $details, $now);
		}
	}

	/* Detection 3: Stale IPs — in IPAM as active but not alive on scan */
	foreach ($ipam_by_ip as $ip => $addr) {
		if ($addr['state'] === 'active' && !isset($scan_alive[$ip])) {
			$details = json_encode(array(
				'ipam_mac'   => $addr['mac_address'] ?? '',
				'ipam_host'  => $addr['hostname'] ?? '',
				'last_state' => $addr['state'],
			));
			$new_conflicts[] = cereus_ipam_record_conflict($subnet_id, $ip, 'stale', $details, $now);
		}
	}

	return $new_conflicts;
}

/**
 * Record a conflict, avoiding duplicates for unresolved conflicts.
 *
 * @param int    $subnet_id
 * @param string $ip
 * @param string $type  mac_conflict|rogue|stale
 * @param string $details JSON details
 * @param string $now  Timestamp
 * @return array|false  The conflict record or false if duplicate
 */
function cereus_ipam_record_conflict($subnet_id, $ip, $type, $details, $now) {
	/* Check for existing unresolved conflict of same type */
	$existing = db_fetch_cell_prepared(
		"SELECT id FROM plugin_cereus_ipam_conflicts
		WHERE subnet_id = ? AND ip = ? AND type = ? AND resolved_at IS NULL",
		array($subnet_id, $ip, $type)
	);

	if ($existing) {
		/* Update details and detection time */
		db_execute_prepared(
			"UPDATE plugin_cereus_ipam_conflicts SET details = ?, detected_at = ? WHERE id = ?",
			array($details, $now, $existing)
		);
		return false;
	}

	/* Insert new conflict */
	db_execute_prepared(
		"INSERT INTO plugin_cereus_ipam_conflicts
			(subnet_id, ip, type, details, detected_at)
		VALUES (?, ?, ?, ?, ?)",
		array($subnet_id, $ip, $type, $details, $now)
	);

	return array(
		'subnet_id' => $subnet_id,
		'ip'        => $ip,
		'type'      => $type,
		'details'   => $details,
	);
}

/**
 * Resolve a conflict (mark as resolved).
 *
 * @param int $conflict_id
 * @return bool
 */
function cereus_ipam_resolve_conflict($conflict_id) {
	$user_id = $_SESSION['sess_user_id'] ?? 0;
	db_execute_prepared(
		"UPDATE plugin_cereus_ipam_conflicts SET resolved_at = NOW(), resolved_by = ? WHERE id = ?",
		array($user_id, $conflict_id)
	);
	return true;
}

/**
 * Resolve all conflicts for a given subnet.
 *
 * @param int $subnet_id
 */
function cereus_ipam_resolve_all_conflicts($subnet_id) {
	$user_id = $_SESSION['sess_user_id'] ?? 0;
	db_execute_prepared(
		"UPDATE plugin_cereus_ipam_conflicts SET resolved_at = NOW(), resolved_by = ? WHERE subnet_id = ? AND resolved_at IS NULL",
		array($user_id, $subnet_id)
	);
}

/**
 * Get active (unresolved) conflicts, optionally filtered by subnet or type.
 *
 * @param int    $subnet_id  0 for all
 * @param string $type       '' for all types
 * @param int    $limit      Max results
 * @return array
 */
function cereus_ipam_get_active_conflicts($subnet_id = 0, $type = '', $limit = 100) {
	$sql = "SELECT c.*, s.subnet, s.mask
		FROM plugin_cereus_ipam_conflicts c
		LEFT JOIN plugin_cereus_ipam_subnets s ON s.id = c.subnet_id
		WHERE c.resolved_at IS NULL";
	$params = array();

	if ($subnet_id > 0) {
		$sql .= " AND c.subnet_id = ?";
		$params[] = $subnet_id;
	}

	if (!empty($type)) {
		$sql .= " AND c.type = ?";
		$params[] = $type;
	}

	$sql .= " ORDER BY c.detected_at DESC LIMIT " . (int) $limit;

	return db_fetch_assoc_prepared($sql, $params);
}

/**
 * Get conflict count summary by type.
 *
 * @return array  e.g. array('mac_conflict' => 3, 'rogue' => 5, 'stale' => 2, 'total' => 10)
 */
function cereus_ipam_conflict_summary() {
	$rows = db_fetch_assoc(
		"SELECT type, COUNT(*) AS cnt
		FROM plugin_cereus_ipam_conflicts
		WHERE resolved_at IS NULL
		GROUP BY type"
	);

	$summary = array('mac_conflict' => 0, 'rogue' => 0, 'stale' => 0, 'total' => 0);
	foreach ($rows as $r) {
		$summary[$r['type']] = (int) $r['cnt'];
		$summary['total'] += (int) $r['cnt'];
	}

	return $summary;
}

/**
 * Get conflict type display info.
 *
 * @param string $type
 * @return array  array('label' => ..., 'color' => ..., 'icon' => ...)
 */
function cereus_ipam_conflict_type_info($type) {
	$types = array(
		'mac_conflict' => array(
			'label' => __('MAC Conflict', 'cereus_ipam'),
			'color' => '#e74c3c',
			'icon'  => 'fa-exclamation-triangle',
		),
		'rogue' => array(
			'label' => __('Rogue/Unmanaged', 'cereus_ipam'),
			'color' => '#f39c12',
			'icon'  => 'fa-question-circle',
		),
		'stale' => array(
			'label' => __('Stale', 'cereus_ipam'),
			'color' => '#95a5a6',
			'icon'  => 'fa-clock-o',
		),
	);

	return $types[$type] ?? array('label' => ucfirst($type), 'color' => '#999', 'icon' => 'fa-info-circle');
}

/**
 * Send email alert for newly detected conflicts.
 * Uses existing threshold email infrastructure.
 *
 * @param array $new_conflicts  Array of new conflict records
 * @param int   $subnet_id
 */
function cereus_ipam_conflict_alert($new_conflicts, $subnet_id) {
	if (!cacti_sizeof($new_conflicts)) {
		return;
	}

	/* Get email recipients */
	$manual_emails  = read_config_option('cereus_ipam_conflict_alert_emails');
	$notify_list_id = (int) read_config_option('cereus_ipam_conflict_notify_list');

	if (function_exists('cereus_ipam_merge_notification_emails')) {
		$emails = cereus_ipam_merge_notification_emails($manual_emails, $notify_list_id);
	} else {
		$emails = trim($manual_emails);
	}

	if (empty($emails)) {
		return;
	}

	/* Build email body */
	$subnet = db_fetch_row_prepared("SELECT subnet, mask, description FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
	$subnet_label = cacti_sizeof($subnet) ? $subnet['subnet'] . '/' . $subnet['mask'] : __('Unknown', 'cereus_ipam');

	$body = '<h2>' . __('IPAM Conflict Alert', 'cereus_ipam') . '</h2>';
	$body .= '<p>' . __('New conflicts detected in subnet %s:', $subnet_label, 'cereus_ipam') . '</p>';
	$body .= '<table border="1" cellpadding="5" cellspacing="0" style="border-collapse:collapse;">';
	$body .= '<tr style="background:#f5f5f5;"><th>' . __('IP', 'cereus_ipam') . '</th><th>' . __('Type', 'cereus_ipam') . '</th><th>' . __('Details', 'cereus_ipam') . '</th></tr>';

	foreach ($new_conflicts as $c) {
		if ($c === false) continue;
		$type_info = cereus_ipam_conflict_type_info($c['type']);
		$details = json_decode($c['details'], true);
		$detail_str = '';
		if (is_array($details)) {
			foreach ($details as $k => $v) {
				if (!empty($v)) {
					$detail_str .= htmlspecialchars($k) . ': ' . htmlspecialchars($v) . '<br>';
				}
			}
		}
		$body .= '<tr>';
		$body .= '<td>' . htmlspecialchars($c['ip']) . '</td>';
		$body .= '<td style="color:' . $type_info['color'] . ';">' . $type_info['label'] . '</td>';
		$body .= '<td>' . $detail_str . '</td>';
		$body .= '</tr>';
	}
	$body .= '</table>';

	$subject = __('[Cereus IPAM] Conflict Alert: %s', $subnet_label, 'cereus_ipam');

	/* Use Cacti's mailer */
	$from_email = read_config_option('settings_from_email');
	$from_name  = read_config_option('settings_from_name');
	if (empty($from_email)) {
		$from_email = 'cacti@' . php_uname('n');
	}

	mailer($from_email, $emails, '', '', '', $subject, $body, '', array(), array(), $from_name);

	cacti_log('CEREUS IPAM: Conflict alert sent for subnet ' . $subnet_label . ' (' . count($new_conflicts) . ' conflicts)', false, 'PLUGIN');
}
