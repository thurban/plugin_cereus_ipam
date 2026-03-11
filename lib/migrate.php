<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2024-2026 Urban-Software.de / Thomas Urban               |
 +-------------------------------------------------------------------------+
 | Cereus IPAM - Migration from nmidPhpip                                  |
 +-------------------------------------------------------------------------+
*/

/**
 * Check if nmidPhpip tables exist.
 */
function cereus_ipam_migration_available() {
	$tables = db_fetch_assoc("SHOW TABLES LIKE 'phpIP%'");
	return cacti_sizeof($tables) > 0;
}

/**
 * Get migration summary without performing migration.
 */
function cereus_ipam_migration_summary() {
	$result = array(
		'available'  => false,
		'sections'   => 0,
		'addresses'  => 0,
	);

	/* Check for phpIP_NetMenu (sections/subnets) */
	$tables = db_fetch_assoc("SHOW TABLES LIKE 'phpIP_NetMenu'");
	if (cacti_sizeof($tables)) {
		$result['available'] = true;
		$result['sections'] = (int) db_fetch_cell("SELECT COUNT(*) FROM phpIP_NetMenu");
	}

	/* Check for phpIP_addresses */
	$tables = db_fetch_assoc("SHOW TABLES LIKE 'phpIP_addresses'");
	if (cacti_sizeof($tables)) {
		$result['addresses'] = (int) db_fetch_cell("SELECT COUNT(*) FROM phpIP_addresses");
	}

	return $result;
}

/**
 * Run the migration from nmidPhpip.
 *
 * Maps:
 *   phpIP_NetMenu -> sections + subnets
 *   phpIP_addresses -> addresses
 */
function cereus_ipam_run_migration() {
	$log = array();
	$sections_migrated = 0;
	$subnets_migrated = 0;
	$addresses_migrated = 0;
	$addresses_skipped = 0;
	$user_id = $_SESSION['sess_user_id'] ?? 0;

	/* Step 1: Create a default section for migrated data */
	db_execute_prepared("INSERT INTO plugin_cereus_ipam_sections
		(name, description, display_order)
		VALUES (?, ?, 0)",
		array(__('Migrated from phpIP', 'cereus_ipam'), __('Data migrated from nmidPhpip plugin', 'cereus_ipam')));
	$default_section_id = db_fetch_insert_id();
	$log[] = __('Created migration section (ID: %d)', $default_section_id, 'cereus_ipam');

	/* Step 2: Migrate phpIP_NetMenu as subnets */
	$tables = db_fetch_assoc("SHOW TABLES LIKE 'phpIP_NetMenu'");
	if (cacti_sizeof($tables)) {
		$menu_items = db_fetch_assoc("SELECT * FROM phpIP_NetMenu ORDER BY id");

		foreach ($menu_items as $item) {
			/* phpIP_NetMenu has: id, net, mask, description, menutype, sortorder, etc. */
			$net  = isset($item['net']) ? trim($item['net']) : '';
			$mask = isset($item['mask']) ? trim($item['mask']) : '';

			if (empty($net)) {
				continue;
			}

			/* Convert dotted mask to CIDR if needed */
			$cidr_mask = $mask;
			if (strpos($mask, '.') !== false) {
				/* Dotted notation, convert to CIDR */
				$cidr_mask = cereus_ipam_dotted_to_cidr($mask);
			}

			$cidr_mask = (int) $cidr_mask;

			/* Validate */
			if (!cereus_ipam_validate_ip($net)) {
				$log[] = __('Skipped invalid network: %s', $net, 'cereus_ipam');
				continue;
			}

			/* Ensure network address */
			$network = cereus_ipam_network_address($net, $cidr_mask);

			$description = isset($item['description']) ? cereus_ipam_sanitize_text($item['description'], 255) : '';

			db_execute_prepared("INSERT IGNORE INTO plugin_cereus_ipam_subnets
				(section_id, subnet, mask, description)
				VALUES (?, ?, ?, ?)",
				array($default_section_id, $network, $cidr_mask, $description));

			$subnets_migrated++;
		}
	}

	$log[] = __('Migrated %d subnets', $subnets_migrated, 'cereus_ipam');

	/* Step 3: Migrate phpIP_addresses */
	$tables = db_fetch_assoc("SHOW TABLES LIKE 'phpIP_addresses'");
	if (cacti_sizeof($tables)) {
		$addresses = db_fetch_assoc("SELECT * FROM phpIP_addresses");

		foreach ($addresses as $addr) {
			$ip = isset($addr['ipaddr']) ? trim($addr['ipaddr']) : '';

			if (empty($ip) || !cereus_ipam_validate_ip($ip)) {
				$addresses_skipped++;
				continue;
			}

			/* Find which subnet this IP belongs to */
			$subnet = db_fetch_row_prepared("SELECT id, subnet, mask FROM plugin_cereus_ipam_subnets
				WHERE section_id = ?
				ORDER BY mask DESC",
				array($default_section_id));

			$matched_subnet_id = null;
			$all_subnets = db_fetch_assoc_prepared("SELECT id, subnet, mask FROM plugin_cereus_ipam_subnets
				WHERE section_id = ?",
				array($default_section_id));

			foreach ($all_subnets as $s) {
				if (cereus_ipam_ip_in_subnet($ip, $s['subnet'], $s['mask'])) {
					$matched_subnet_id = $s['id'];
					break;
				}
			}

			if ($matched_subnet_id === null) {
				$addresses_skipped++;
				continue;
			}

			$hostname    = isset($addr['name']) ? cereus_ipam_sanitize_text($addr['name'], 255) : '';
			$description = isset($addr['descr']) ? cereus_ipam_sanitize_text($addr['descr'], 255) : '';
			$mac_address = '';
			if (isset($addr['macaddr']) && !empty($addr['macaddr'])) {
				$mac = cereus_ipam_normalize_mac($addr['macaddr']);
				if ($mac !== false) {
					$mac_address = $mac;
				}
			}

			/* Check Cacti device link */
			$cacti_host_id = null;
			if (isset($addr['isCactiDevice']) && $addr['isCactiDevice'] == 1) {
				$host = db_fetch_row_prepared("SELECT id FROM host WHERE hostname = ?", array($ip));
				if (cacti_sizeof($host)) {
					$cacti_host_id = $host['id'];
				}
			}

			db_execute_prepared("INSERT IGNORE INTO plugin_cereus_ipam_addresses
				(subnet_id, ip, hostname, description, mac_address, state, cacti_host_id, created_by)
				VALUES (?, ?, ?, ?, ?, 'active', ?, ?)",
				array($matched_subnet_id, $ip, $hostname, $description, $mac_address, $cacti_host_id, $user_id));

			$addresses_migrated++;
		}
	}

	$log[] = __('Migrated %d addresses, skipped %d', $addresses_migrated, $addresses_skipped, 'cereus_ipam');

	/* Log migration in changelog */
	cereus_ipam_changelog_record(
		CEREUS_IPAM_ACTION_IMPORT,
		CEREUS_IPAM_OBJ_SECTION,
		$default_section_id,
		null,
		array('subnets' => $subnets_migrated, 'addresses' => $addresses_migrated)
	);

	return array(
		'success'            => true,
		'section_id'         => $default_section_id,
		'subnets_migrated'   => $subnets_migrated,
		'addresses_migrated' => $addresses_migrated,
		'addresses_skipped'  => $addresses_skipped,
		'log'                => $log,
	);
}

/**
 * Convert dotted-decimal subnet mask to CIDR prefix length.
 */
function cereus_ipam_dotted_to_cidr($mask) {
	$long = ip2long($mask);
	if ($long === false) {
		return 24; /* default fallback */
	}
	$binary = sprintf('%032b', $long);
	return strlen(rtrim($binary, '0'));
}
