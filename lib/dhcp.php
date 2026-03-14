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
 | Cereus IPAM - DHCP Scope Monitoring                                     |
 +-------------------------------------------------------------------------+
*/

/**
 * Resolve the full OID for an SNMP GET by appending the scope subnet index
 * when the OID is a Microsoft DHCP MIB base OID without an index.
 *
 * Microsoft DHCP MIB OIDs (.1.3.6.1.4.1.311.1.3.2.1.1.X) are table columns
 * indexed by the scope's subnet IP.  For example, scope 192.168.1.0 uses:
 *   .1.3.6.1.4.1.311.1.3.2.1.1.2.192.168.1.0  (active leases)
 *
 * If the user enters a full OID with index, it is used as-is.
 * If the user enters a base OID (column only), the linked subnet's network
 * address is appended automatically.
 *
 * @param string $oid        The OID from the scope configuration.
 * @param string $subnet_ip  The subnet network address (e.g. "192.168.1.0").
 * @return string The resolved OID ready for SNMP GET.
 */
function cereus_ipam_dhcp_resolve_oid($oid, $subnet_ip) {
	$oid = trim($oid);

	if (empty($oid) || empty($subnet_ip)) {
		return $oid;
	}

	/* Microsoft DHCP MIB base: .1.3.6.1.4.1.311.1.3.2.1.1 */
	$ms_dhcp_base = '.1.3.6.1.4.1.311.1.3.2.1.1';

	/* Check if this is a Microsoft DHCP MIB OID */
	if (strpos($oid, $ms_dhcp_base) === 0) {
		/* Strip the base to see what's left */
		$suffix = substr($oid, strlen($ms_dhcp_base));

		/* Expected patterns:
		 *   .2           → column only, needs index appended
		 *   .2.10.0.1.0  → column + index, already complete
		 * Count the dot-separated parts after the base */
		$parts = explode('.', ltrim($suffix, '.'));

		if (count($parts) <= 1) {
			/* Only column number — append subnet IP as index */
			return $oid . '.' . $subnet_ip;
		}

		/* More than 1 part after base — user supplied an index already */
		return $oid;
	}

	/* Non-Microsoft OID: check if it looks like a table OID without index.
	 * Heuristic: if the OID has fewer than 15 dot-separated parts, it likely
	 * needs an index. But we can't know for sure, so leave it as-is for
	 * non-Microsoft OIDs — the user knows their MIB. */
	return $oid;
}

/**
 * Poll a single DHCP scope via SNMP and update the DB.
 * Uses Cacti's cacti_snmp_get() if server_host_id is set, otherwise direct SNMP.
 *
 * Auto-appends the subnet IP to Microsoft DHCP MIB OIDs when missing.
 *
 * @param int $scope_id The DHCP scope ID to poll.
 * @return array Result with 'success', 'active', 'total', 'free', 'errors'.
 */
function cereus_ipam_dhcp_poll_scope($scope_id) {
	global $config;

	if (!function_exists('cacti_snmp_get')) {
		include_once($config['library_path'] . '/snmp.php');
	}

	$scope = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_dhcp_scopes WHERE id = ?", array($scope_id));

	if (!cacti_sizeof($scope)) {
		cacti_log('CEREUS IPAM DHCP: Scope ID ' . $scope_id . ' not found.', false, 'PLUGIN');
		return array('success' => false, 'errors' => array('Scope not found.'));
	}

	/* Get the linked subnet's network address for OID index resolution */
	$subnet_ip = '';
	if (!empty($scope['subnet_id'])) {
		$subnet_ip = db_fetch_cell_prepared("SELECT subnet FROM plugin_cereus_ipam_subnets WHERE id = ?",
			array($scope['subnet_id']));
		if (empty($subnet_ip)) {
			$subnet_ip = '';
		}
	}

	if (empty($subnet_ip)) {
		cacti_log('CEREUS IPAM DHCP: Scope ' . $scope_id . ' (' . ($scope['scope_name'] ?? '') . ') has no linked subnet (subnet_id=' . ($scope['subnet_id'] ?? 'NULL') . '). Microsoft DHCP OIDs require a subnet link for index resolution.', false, 'PLUGIN');
	}

	/* Resolve OIDs — auto-append subnet index for Microsoft DHCP MIB */
	$oid_active = cereus_ipam_dhcp_resolve_oid($scope['oid_active'], $subnet_ip);
	$oid_total  = cereus_ipam_dhcp_resolve_oid($scope['oid_total'], $subnet_ip);
	$oid_free   = cereus_ipam_dhcp_resolve_oid($scope['oid_free'], $subnet_ip);

	if (read_config_option('cereus_ipam_debug') == 'on') {
		cacti_log('CEREUS IPAM DHCP: Scope ' . $scope_id . ' OID resolve: subnet_id=' . ($scope['subnet_id'] ?? 'NULL') . ', subnet_ip=' . ($subnet_ip ?: 'EMPTY') . ', active=' . $oid_active . ', total=' . $oid_total . ', free=' . $oid_free, false, 'PLUGIN');
	}

	$active = false;
	$total  = false;
	$free   = false;

	if (!empty($scope['server_host_id'])) {
		/* Use Cacti host SNMP settings */
		$host = db_fetch_row_prepared("SELECT * FROM host WHERE id = ?", array($scope['server_host_id']));

		if (!cacti_sizeof($host)) {
			cacti_log('CEREUS IPAM DHCP: Host ID ' . $scope['server_host_id'] . ' not found for scope ' . $scope_id . '.', false, 'PLUGIN');
			return array('success' => false, 'errors' => array('Cacti host not found.'));
		}

		$active = @cacti_snmp_get(
			$host['hostname'], $host['snmp_community'], $oid_active,
			$host['snmp_version'], $host['snmp_username'], $host['snmp_password'],
			$host['snmp_auth_protocol'], $host['snmp_priv_passphrase'], $host['snmp_priv_protocol'],
			$host['snmp_context'], $host['snmp_port'], $host['snmp_timeout']
		);

		$total = @cacti_snmp_get(
			$host['hostname'], $host['snmp_community'], $oid_total,
			$host['snmp_version'], $host['snmp_username'], $host['snmp_password'],
			$host['snmp_auth_protocol'], $host['snmp_priv_passphrase'], $host['snmp_priv_protocol'],
			$host['snmp_context'], $host['snmp_port'], $host['snmp_timeout']
		);

		$free = @cacti_snmp_get(
			$host['hostname'], $host['snmp_community'], $oid_free,
			$host['snmp_version'], $host['snmp_username'], $host['snmp_password'],
			$host['snmp_auth_protocol'], $host['snmp_priv_passphrase'], $host['snmp_priv_protocol'],
			$host['snmp_context'], $host['snmp_port'], $host['snmp_timeout']
		);
	} else {
		/* Direct SNMP using server_ip — use SNMPv2c with default community */
		$community = read_config_option('snmp_community');
		if (empty($community)) {
			$community = 'public';
		}

		$active = @cacti_snmp_get($scope['server_ip'], $community, $oid_active,
			2, '', '', '', '', '', '', 161, 1000);

		$total = @cacti_snmp_get($scope['server_ip'], $community, $oid_total,
			2, '', '', '', '', '', '', 161, 1000);

		$free = @cacti_snmp_get($scope['server_ip'], $community, $oid_free,
			2, '', '', '', '', '', '', 161, 1000);
	}

	/* Check for SNMP errors — report which OIDs failed */
	$errors = array();

	if (!is_numeric($active)) {
		$errors[] = 'Active Leases OID (' . $oid_active . ') returned: ' . (empty($active) ? 'empty/timeout' : $active);
	}
	if (!is_numeric($total)) {
		$errors[] = 'Total Leases OID (' . $oid_total . ') returned: ' . (empty($total) ? 'empty/timeout' : $total);
	}
	if (!is_numeric($free)) {
		$errors[] = 'Free Leases OID (' . $oid_free . ') returned: ' . (empty($free) ? 'empty/timeout' : $free);
	}

	$active_val = is_numeric($active) ? (int) $active : 0;
	$total_val  = is_numeric($total)  ? (int) $total  : 0;
	$free_val   = is_numeric($free)   ? (int) $free   : 0;
	$has_data   = is_numeric($active) || is_numeric($total) || is_numeric($free);

	/* Update scope record */
	db_execute_prepared("UPDATE plugin_cereus_ipam_dhcp_scopes
		SET active_leases = ?, total_leases = ?, free_leases = ?, last_polled = NOW()
		WHERE id = ?",
		array($active_val, $total_val, $free_val, $scope_id)
	);

	if (!empty($errors)) {
		cacti_log('CEREUS IPAM DHCP: Scope ' . $scope_id . ' (' . $scope['scope_name'] . ') SNMP errors: ' . implode('; ', $errors), false, 'PLUGIN');
	}

	if (read_config_option('cereus_ipam_debug') == 'on') {
		cacti_log('CEREUS IPAM DHCP: Polled scope ' . $scope_id . ' (' . $scope['scope_name'] . '): active=' . $active_val . ', total=' . $total_val . ', free=' . $free_val . ' (OIDs: ' . $oid_active . ', ' . $oid_total . ', ' . $oid_free . ')', false, 'PLUGIN');
	}

	return array(
		'success' => $has_data,
		'active'  => $active_val,
		'total'   => $total_val,
		'free'    => $free_val,
		'errors'  => $errors,
		'oids'    => array('active' => $oid_active, 'total' => $oid_total, 'free' => $oid_free),
	);
}

/**
 * Poll all enabled DHCP scopes that are due (last_polled + poll_interval < NOW).
 * Called from poller_bottom.
 */
function cereus_ipam_dhcp_poll_all() {
	$scopes = db_fetch_assoc("SELECT id, scope_name
		FROM plugin_cereus_ipam_dhcp_scopes
		WHERE enabled = 1
		AND (last_polled IS NULL OR last_polled < DATE_SUB(NOW(), INTERVAL poll_interval SECOND))");

	if (!cacti_sizeof($scopes)) {
		return;
	}

	if (read_config_option('cereus_ipam_debug') == 'on') {
		cacti_log('CEREUS IPAM DHCP: Polling ' . cacti_sizeof($scopes) . ' scope(s).', false, 'PLUGIN');
	}

	foreach ($scopes as $scope) {
		cereus_ipam_dhcp_poll_scope($scope['id']);
	}
}

/**
 * Get DHCP scope info for a subnet (if any configured).
 * Returns array with active_leases, total_leases, free_leases, utilization_pct, last_polled.
 *
 * @param int $subnet_id The subnet ID.
 * @return array|false Scope info array or false if none configured.
 */
function cereus_ipam_dhcp_get_scope_info($subnet_id) {
	$scope = db_fetch_row_prepared("SELECT active_leases, total_leases, free_leases, last_polled
		FROM plugin_cereus_ipam_dhcp_scopes
		WHERE subnet_id = ? AND enabled = 1
		LIMIT 1",
		array($subnet_id)
	);

	if (!cacti_sizeof($scope)) {
		return false;
	}

	$utilization_pct = 0;
	if ($scope['total_leases'] > 0) {
		$utilization_pct = round(($scope['active_leases'] / $scope['total_leases']) * 100, 1);
	}

	$scope['utilization_pct'] = $utilization_pct;

	return $scope;
}

/**
 * Get all DHCP scopes with joined subnet info.
 *
 * @param string $filter  Search filter text.
 * @param int    $rows    Rows per page.
 * @param int    $page    Current page number.
 * @param string $sort_column  Column to sort by.
 * @param string $sort_direction  Sort direction (ASC/DESC).
 * @return array Array of scope rows.
 */
function cereus_ipam_dhcp_get_all_scopes($filter = '', $rows = 30, $page = 1, $sort_column = 'scope_name', $sort_direction = 'ASC') {
	$sql_where  = 'WHERE 1=1';
	$sql_params = array();

	if (!empty($filter)) {
		$safe = str_replace(array('%', '_'), array('\\%', '\\_'), $filter);
		$sql_where .= ' AND (d.scope_name LIKE ? OR d.server_ip LIKE ? OR s.subnet LIKE ? OR s.description LIKE ?)';
		$sql_params[] = '%' . $safe . '%';
		$sql_params[] = '%' . $safe . '%';
		$sql_params[] = '%' . $safe . '%';
		$sql_params[] = '%' . $safe . '%';
	}

	/* Whitelist sort columns */
	$allowed_sorts = array('scope_name', 'server_ip', 'active_leases', 'total_leases', 'free_leases', 'last_polled', 'enabled', 'subnet');
	if (!in_array($sort_column, $allowed_sorts, true)) {
		$sort_column = 'scope_name';
	}
	$sort_direction = (strtoupper($sort_direction) === 'DESC') ? 'DESC' : 'ASC';

	/* Prefix sort column with table alias */
	$sort_prefix = 'd.';
	if ($sort_column === 'subnet') {
		$sort_prefix = 's.';
	}

	$offset = (max(1, (int) $page) - 1) * max(1, (int) $rows);

	return db_fetch_assoc_prepared(
		"SELECT d.*, s.subnet, s.mask, s.description AS subnet_desc,
			h.description AS host_desc, h.hostname AS host_hostname
		FROM plugin_cereus_ipam_dhcp_scopes d
		LEFT JOIN plugin_cereus_ipam_subnets s ON s.id = d.subnet_id
		LEFT JOIN host h ON h.id = d.server_host_id
		$sql_where
		ORDER BY $sort_prefix$sort_column $sort_direction
		LIMIT $offset, $rows",
		$sql_params
	);
}

/**
 * Get total count of DHCP scopes matching filter.
 *
 * @param string $filter Search filter text.
 * @return int Count of matching scopes.
 */
function cereus_ipam_dhcp_get_scope_count($filter = '') {
	$sql_where  = 'WHERE 1=1';
	$sql_params = array();

	if (!empty($filter)) {
		$safe = str_replace(array('%', '_'), array('\\%', '\\_'), $filter);
		$sql_where .= ' AND (d.scope_name LIKE ? OR d.server_ip LIKE ? OR s.subnet LIKE ? OR s.description LIKE ?)';
		$sql_params[] = '%' . $safe . '%';
		$sql_params[] = '%' . $safe . '%';
		$sql_params[] = '%' . $safe . '%';
		$sql_params[] = '%' . $safe . '%';
	}

	return (int) db_fetch_cell_prepared(
		"SELECT COUNT(*)
		FROM plugin_cereus_ipam_dhcp_scopes d
		LEFT JOIN plugin_cereus_ipam_subnets s ON s.id = d.subnet_id
		$sql_where",
		$sql_params
	);
}
