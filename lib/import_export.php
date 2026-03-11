<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2024-2026 Urban-Software.de / Thomas Urban               |
 +-------------------------------------------------------------------------+
 | Cereus IPAM - CSV Import/Export                                         |
 +-------------------------------------------------------------------------+
*/

/**
 * Strip CIDR notation from an IP address string.
 *
 * "10.0.0.1/24" → "10.0.0.1", "10.0.0.1" → "10.0.0.1", "2001:db8::1/64" → "2001:db8::1"
 *
 * @param string $ip_string IP address possibly with /prefix
 * @return string IP address without prefix
 */
function cereus_ipam_strip_cidr($ip_string) {
	$ip_string = trim($ip_string);
	if (strpos($ip_string, '/') !== false) {
		$parts = explode('/', $ip_string, 2);
		return trim($parts[0]);
	}
	return $ip_string;
}

/**
 * Detect CSV format from header row.
 *
 * @param array $header Array of lowercased/trimmed header column names
 * @return string One of: 'cereus', 'phpipam', 'netbox', 'unknown'
 */
function cereus_ipam_detect_csv_format($header) {
	if (in_array('ip_addr', $header) || in_array('ip addr', $header)) {
		return 'phpipam';
	}

	if (in_array('address', $header) && (in_array('vrf', $header) || in_array('tenant', $header) || (in_array('status', $header) && in_array('dns_name', $header)))) {
		return 'netbox';
	}

	if (in_array('ip', $header)) {
		return 'cereus';
	}

	return 'unknown';
}

/**
 * Map phpIPAM CSV columns to internal column indices.
 *
 * phpIPAM columns: ip_addr/ip addr, hostname, description, mac, owner, state, switch, port, note
 *
 * @param array $header Array of lowercased/trimmed header column names
 * @return array Column map with 'ip', 'hostname', 'description', etc. => column index or false
 */
function cereus_ipam_map_phpipam_columns($header) {
	$ip_col = array_search('ip_addr', $header);
	if ($ip_col === false) {
		$ip_col = array_search('ip addr', $header);
	}

	$port_col = array_search('port', $header);
	$switch_col = array_search('switch', $header);

	return array(
		'ip'          => $ip_col,
		'hostname'    => array_search('hostname', $header),
		'description' => array_search('description', $header),
		'mac_address' => array_search('mac', $header),
		'state'       => array_search('state', $header),
		'owner'       => array_search('owner', $header),
		'device_type' => false,
		'note'        => array_search('note', $header),
		'port'        => ($port_col !== false) ? $port_col : $switch_col,
	);
}

/**
 * Map NetBox CSV columns to internal column indices.
 *
 * NetBox columns: address, vrf, tenant, status, role, dns_name, description, tags
 *
 * @param array $header Array of lowercased/trimmed header column names
 * @return array Column map with 'ip', 'hostname', 'description', etc. => column index or false
 */
function cereus_ipam_map_netbox_columns($header) {
	return array(
		'ip'          => array_search('address', $header),
		'hostname'    => array_search('dns_name', $header),
		'description' => array_search('description', $header),
		'mac_address' => false,
		'state'       => array_search('status', $header),
		'owner'       => array_search('tenant', $header),
		'device_type' => array_search('role', $header),
		'note'        => array_search('tags', $header),
	);
}

/**
 * Map phpIPAM state values to internal state values.
 *
 * @param string $state phpIPAM state value (case-insensitive)
 * @return string Internal state value
 */
function cereus_ipam_map_phpipam_state($state) {
	$state = strtolower(trim($state));
	$map = array(
		'active'   => 'active',
		'reserved' => 'reserved',
		'offline'  => 'offline',
		'dhcp'     => 'dhcp',
	);
	return isset($map[$state]) ? $map[$state] : 'active';
}

/**
 * Map NetBox status values to internal state values.
 *
 * @param string $status NetBox status value (case-insensitive)
 * @return string Internal state value
 */
function cereus_ipam_map_netbox_state($status) {
	$status = strtolower(trim($status));
	$map = array(
		'active'     => 'active',
		'reserved'   => 'reserved',
		'deprecated' => 'offline',
		'dhcp'       => 'dhcp',
		'planned'    => 'available',
	);
	return isset($map[$status]) ? $map[$status] : 'active';
}

/**
 * Process a CSV import file.
 *
 * Expected CSV columns: ip, hostname, description, mac_address, state, owner, device_type, note
 * Also supports phpIPAM and NetBox CSV export formats via auto-detection or explicit format.
 *
 * @param int    $subnet_id Target subnet
 * @param string $file_path Path to uploaded CSV file
 * @param string $format    CSV format: 'auto', 'cereus', 'phpipam', 'netbox' (default 'auto')
 * @return array Result with 'success', 'imported', 'skipped', 'errors'
 */
function cereus_ipam_import_csv($subnet_id, $file_path, $format = 'auto') {
	$subnet = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
	if (!cacti_sizeof($subnet)) {
		return array('success' => false, 'error' => __('Subnet not found.', 'cereus_ipam'));
	}

	$max_rows = cereus_ipam_license_max_import_rows();
	$fh = fopen($file_path, 'r');
	if ($fh === false) {
		return array('success' => false, 'error' => __('Cannot open file.', 'cereus_ipam'));
	}

	/* Read header row */
	$header = fgetcsv($fh);
	if ($header === false) {
		fclose($fh);
		return array('success' => false, 'error' => __('Empty file or invalid CSV.', 'cereus_ipam'));
	}

	/* Normalize headers */
	$header = array_map(function($h) { return strtolower(trim($h)); }, $header);

	/* Detect or validate format */
	if ($format === 'auto') {
		$format = cereus_ipam_detect_csv_format($header);
	}

	$strip_cidr = false;

	if ($format === 'phpipam') {
		$col_map = cereus_ipam_map_phpipam_columns($header);
		$ip_col = $col_map['ip'];
		$strip_cidr = true;
	} elseif ($format === 'netbox') {
		$col_map = cereus_ipam_map_netbox_columns($header);
		$ip_col = $col_map['ip'];
		$strip_cidr = true;
	} else {
		/* Cereus native or unknown — use original logic */
		$ip_col = array_search('ip', $header);

		if ($ip_col === false) {
			$ip_col = array_search('ip_address', $header);
			if ($ip_col === false) {
				$ip_col = array_search('address', $header);
			}
		}

		$col_map = array(
			'hostname'    => array_search('hostname', $header),
			'description' => array_search('description', $header),
			'mac_address' => array_search('mac_address', $header),
			'state'       => array_search('state', $header),
			'owner'       => array_search('owner', $header),
			'device_type' => array_search('device_type', $header),
			'note'        => array_search('note', $header),
		);
	}

	if ($ip_col === false) {
		fclose($fh);
		return array('success' => false, 'error' => __('CSV must have an IP column (ip, ip_addr, or address).', 'cereus_ipam'));
	}

	$imported = 0;
	$skipped  = 0;
	$errors   = array();
	$row_num  = 1;
	$user_id  = $_SESSION['sess_user_id'] ?? 0;

	while (($row = fgetcsv($fh)) !== false) {
		$row_num++;

		/* License limit check */
		if ($max_rows > 0 && $imported >= $max_rows) {
			$errors[] = __('Row %d: Import limit reached (%d rows). Upgrade for unlimited imports.', $row_num, $max_rows, 'cereus_ipam');
			break;
		}

		$ip = isset($row[$ip_col]) ? trim($row[$ip_col]) : '';
		if (empty($ip)) {
			$skipped++;
			continue;
		}

		/* Strip CIDR prefix if needed (phpIPAM and NetBox include /prefix) */
		if ($strip_cidr) {
			$ip = cereus_ipam_strip_cidr($ip);
		}

		/* Validate IP */
		if (!cereus_ipam_validate_ip($ip)) {
			$errors[] = __('Row %d: Invalid IP address "%s"', $row_num, htmlspecialchars($ip), 'cereus_ipam');
			$skipped++;
			continue;
		}

		/* Check IP is within subnet */
		if (!cereus_ipam_ip_in_subnet($ip, $subnet['subnet'], $subnet['mask'])) {
			$errors[] = __('Row %d: IP "%s" is not within subnet %s/%s', $row_num, $ip, $subnet['subnet'], $subnet['mask'], 'cereus_ipam');
			$skipped++;
			continue;
		}

		/* Build record */
		$hostname    = ($col_map['hostname'] !== false && isset($row[$col_map['hostname']])) ? cereus_ipam_sanitize_text($row[$col_map['hostname']], 255) : '';
		$description = ($col_map['description'] !== false && isset($row[$col_map['description']])) ? cereus_ipam_sanitize_text($row[$col_map['description']], 255) : '';
		$mac_address = '';
		if ($col_map['mac_address'] !== false && isset($row[$col_map['mac_address']]) && !empty($row[$col_map['mac_address']])) {
			$mac_norm = cereus_ipam_normalize_mac($row[$col_map['mac_address']]);
			if ($mac_norm !== false) {
				$mac_address = $mac_norm;
			}
		}

		/* State mapping depends on source format */
		if ($format === 'phpipam') {
			$state = ($col_map['state'] !== false && isset($row[$col_map['state']])) ? cereus_ipam_map_phpipam_state($row[$col_map['state']]) : 'active';
		} elseif ($format === 'netbox') {
			$state = ($col_map['state'] !== false && isset($row[$col_map['state']])) ? cereus_ipam_map_netbox_state($row[$col_map['state']]) : 'active';
		} else {
			$state = ($col_map['state'] !== false && isset($row[$col_map['state']])) ? strtolower(trim($row[$col_map['state']])) : 'active';
			if (!cereus_ipam_validate_state($state)) {
				$state = 'active';
			}
		}

		$owner       = ($col_map['owner'] !== false && isset($row[$col_map['owner']])) ? cereus_ipam_sanitize_text($row[$col_map['owner']], 255) : '';
		$device_type = ($col_map['device_type'] !== false && isset($row[$col_map['device_type']])) ? cereus_ipam_sanitize_text($row[$col_map['device_type']], 128) : '';
		$note        = ($col_map['note'] !== false && isset($row[$col_map['note']])) ? cereus_ipam_sanitize_text($row[$col_map['note']], 65535) : '';

		/* Insert or update */
		$existing = db_fetch_cell_prepared("SELECT id FROM plugin_cereus_ipam_addresses WHERE subnet_id = ? AND ip = ?",
			array($subnet_id, $ip));

		if ($existing) {
			db_execute_prepared("UPDATE plugin_cereus_ipam_addresses SET
				hostname = ?, description = ?, mac_address = ?, state = ?,
				owner = ?, device_type = ?, note = ?
				WHERE id = ?",
				array($hostname, $description, $mac_address, $state, $owner, $device_type, $note, $existing));
		} else {
			db_execute_prepared("INSERT INTO plugin_cereus_ipam_addresses
				(subnet_id, ip, hostname, description, mac_address, state, owner, device_type, note, created_by)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
				array($subnet_id, $ip, $hostname, $description, $mac_address, $state, $owner, $device_type, $note, $user_id));
		}

		$imported++;
	}

	fclose($fh);

	/* Log the import in changelog */
	cereus_ipam_changelog_record(
		CEREUS_IPAM_ACTION_IMPORT,
		CEREUS_IPAM_OBJ_SUBNET,
		$subnet_id,
		null,
		array('imported' => $imported, 'skipped' => $skipped, 'errors' => count($errors))
	);

	return array(
		'success'  => true,
		'imported' => $imported,
		'skipped'  => $skipped,
		'errors'   => $errors,
	);
}

/**
 * Export addresses from a subnet as CSV.
 */
function cereus_ipam_export_csv($subnet_id) {
	$subnet = db_fetch_row_prepared("SELECT subnet, mask FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
	if (!cacti_sizeof($subnet)) {
		return;
	}

	$addresses = db_fetch_assoc_prepared("SELECT ip, hostname, description, mac_address, state, owner, device_type, note
		FROM plugin_cereus_ipam_addresses
		WHERE subnet_id = ?
		ORDER BY INET_ATON(ip)",
		array($subnet_id));

	$filename = 'ipam_' . str_replace(array('/', '.', ':'), '_', $subnet['subnet'] . '_' . $subnet['mask']) . '_' . date('Ymd_His') . '.csv';

	header('Content-Type: text/csv; charset=UTF-8');
	header('Content-Disposition: attachment; filename="' . $filename . '"');

	$fh = fopen('php://output', 'w');
	fputcsv($fh, array('ip', 'hostname', 'description', 'mac_address', 'state', 'owner', 'device_type', 'note'));

	foreach ($addresses as $addr) {
		fputcsv($fh, array(
			$addr['ip'],
			$addr['hostname'],
			$addr['description'],
			$addr['mac_address'],
			$addr['state'],
			$addr['owner'],
			$addr['device_type'],
			$addr['note'],
		));
	}

	fclose($fh);
	exit;
}
