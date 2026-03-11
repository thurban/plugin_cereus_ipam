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
 | Cereus IPAM - REST API Endpoints (Enterprise)                           |
 +-------------------------------------------------------------------------+
*/

/**
 * Hook callback for restapi_register_endpoints.
 * Registers all Cereus IPAM REST API endpoints.
 */
function cereus_ipam_restapi_endpoints($endpoints) {
	global $config;

	include_once($config['base_path'] . '/plugins/cereus_ipam/includes/constants.php');
	include_once($config['base_path'] . '/plugins/cereus_ipam/lib/license_check.php');
	include_once($config['base_path'] . '/plugins/cereus_ipam/lib/validation.php');
	include_once($config['base_path'] . '/plugins/cereus_ipam/lib/ip_utils.php');
	include_once($config['base_path'] . '/plugins/cereus_ipam/lib/functions.php');
	include_once($config['base_path'] . '/plugins/cereus_ipam/lib/changelog.php');

	$file = $config['base_path'] . '/plugins/cereus_ipam/lib/restapi_endpoints.php';

	$endpoints[] = array(
		'resource'    => 'ipam/sections',
		'callback'    => 'cereus_ipam_restapi_sections',
		'file'        => $file,
		'plugin'      => 'cereus_ipam',
		'methods'     => 'GET,POST,PUT,DELETE',
		'description' => 'IPAM sections',
	);

	$endpoints[] = array(
		'resource'    => 'ipam/subnets',
		'callback'    => 'cereus_ipam_restapi_subnets',
		'file'        => $file,
		'plugin'      => 'cereus_ipam',
		'methods'     => 'GET,POST,PUT,DELETE',
		'description' => 'IPAM subnets with utilization',
	);

	$endpoints[] = array(
		'resource'    => 'ipam/addresses',
		'callback'    => 'cereus_ipam_restapi_addresses',
		'file'        => $file,
		'plugin'      => 'cereus_ipam',
		'methods'     => 'GET,POST,PUT,DELETE',
		'description' => 'IPAM IP address management',
	);

	$endpoints[] = array(
		'resource'    => 'ipam/vlans',
		'callback'    => 'cereus_ipam_restapi_vlans',
		'file'        => $file,
		'plugin'      => 'cereus_ipam',
		'methods'     => 'GET,POST,PUT,DELETE',
		'description' => 'IPAM VLAN management',
	);

	$endpoints[] = array(
		'resource'    => 'ipam/vrfs',
		'callback'    => 'cereus_ipam_restapi_vrfs',
		'file'        => $file,
		'plugin'      => 'cereus_ipam',
		'methods'     => 'GET,POST,PUT,DELETE',
		'description' => 'IPAM VRF management',
	);

	return $endpoints;
}

/* =========================================================================
 * Sections Endpoint
 * ========================================================================= */

/**
 * GET    /ipam/sections         — List all sections
 * GET    /ipam/sections/{id}    — Get single section
 * POST   /ipam/sections         — Create section
 * PUT    /ipam/sections/{id}    — Update section
 * DELETE /ipam/sections/{id}    — Delete section
 */
function cereus_ipam_restapi_sections($context) {
	if (!cereus_ipam_license_has_restapi()) {
		restapi_error(403, 'license_required', 'IPAM REST API requires Enterprise license');
		return;
	}

	switch ($context['method']) {
		case 'GET':
			if ($context['id'] !== null) {
				cereus_ipam_restapi_get_section($context);
			} else {
				cereus_ipam_restapi_list_sections($context);
			}

			break;

		case 'POST':
			if ($context['id'] !== null) {
				restapi_error(400, 'invalid_request', 'POST to a specific section ID is not supported');
				return;
			}

			cereus_ipam_restapi_create_section($context);

			break;

		case 'PUT':
			if ($context['id'] === null) {
				restapi_error(400, 'missing_id', 'Section ID is required for updates');
				return;
			}

			cereus_ipam_restapi_update_section($context);

			break;

		case 'DELETE':
			if ($context['id'] === null) {
				restapi_error(400, 'missing_id', 'Section ID is required for deletion');
				return;
			}

			cereus_ipam_restapi_delete_section($context);

			break;

		default:
			restapi_error(405, 'method_not_allowed', 'Supported methods: GET, POST, PUT, DELETE');
	}
}

/**
 * List all sections.
 */
function cereus_ipam_restapi_list_sections($context) {
	$sections = db_fetch_assoc_prepared(
		'SELECT id, parent_id, name, description, permissions, display_order, created, modified
		FROM plugin_cereus_ipam_sections
		ORDER BY display_order, name',
		array()
	);

	if (!is_array($sections)) {
		$sections = array();
	}

	restapi_response($sections);
}

/**
 * Get a single section by ID.
 */
function cereus_ipam_restapi_get_section($context) {
	$id = intval($context['id']);

	if ($id <= 0) {
		restapi_error(400, 'invalid_id', 'Invalid section ID');
		return;
	}

	$section = db_fetch_row_prepared(
		'SELECT id, parent_id, name, description, permissions, display_order, created, modified
		FROM plugin_cereus_ipam_sections
		WHERE id = ?',
		array($id)
	);

	if (!cacti_sizeof($section)) {
		restapi_error(404, 'not_found', "Section with ID $id not found");
		return;
	}

	restapi_response($section);
}

/**
 * Create a new section.
 */
function cereus_ipam_restapi_create_section($context) {
	$input = json_decode(file_get_contents('php://input'), true);

	if (!is_array($input)) {
		restapi_error(400, 'invalid_body', 'Request body must be valid JSON');
		return;
	}

	/* Required fields */
	if (empty($input['name'])) {
		restapi_error(400, 'missing_fields', 'Field name is required');
		return;
	}

	$name          = cereus_ipam_sanitize_text($input['name']);
	$parent_id     = isset($input['parent_id'])     ? intval($input['parent_id'])                          : null;
	$description   = isset($input['description'])   ? cereus_ipam_sanitize_text($input['description'])     : '';
	$permissions   = isset($input['permissions'])    ? cereus_ipam_sanitize_text($input['permissions'])     : '';
	$display_order = isset($input['display_order'])  ? intval($input['display_order'])                     : 0;

	/* Validate name not empty after sanitization */
	if ($name === '') {
		restapi_error(400, 'invalid_name', 'Section name cannot be empty');
		return;
	}

	/* Validate parent_id if provided */
	if ($parent_id !== null && $parent_id > 0) {
		$parent_exists = db_fetch_cell_prepared(
			'SELECT COUNT(*) FROM plugin_cereus_ipam_sections WHERE id = ?',
			array($parent_id)
		);

		if ($parent_exists == 0) {
			restapi_error(400, 'invalid_parent', "Parent section with ID $parent_id not found");
			return;
		}
	}

	db_execute_prepared(
		"INSERT INTO plugin_cereus_ipam_sections
			(parent_id, name, description, permissions, display_order)
		VALUES (?, ?, ?, ?, ?)",
		array($parent_id, $name, $description, $permissions, $display_order)
	);

	$new_id = db_fetch_insert_id();

	if (empty($new_id)) {
		restapi_error(500, 'create_failed', 'Failed to create section');
		return;
	}

	$created = db_fetch_row_prepared(
		'SELECT id, parent_id, name, description, permissions, display_order, created, modified
		FROM plugin_cereus_ipam_sections
		WHERE id = ?',
		array($new_id)
	);

	cacti_log("RESTAPI IPAM: Section '$name' created (ID: $new_id) by user_id " . $context['user_id'], false, 'CEREUS_IPAM');

	cereus_ipam_changelog_record(
		CEREUS_IPAM_ACTION_CREATE,
		CEREUS_IPAM_OBJ_SECTION,
		$new_id,
		null,
		$input
	);

	restapi_response($created, 201);
}

/**
 * Update an existing section.
 */
function cereus_ipam_restapi_update_section($context) {
	$id = intval($context['id']);

	if ($id <= 0) {
		restapi_error(400, 'invalid_id', 'Invalid section ID');
		return;
	}

	$existing = db_fetch_row_prepared(
		'SELECT * FROM plugin_cereus_ipam_sections WHERE id = ?',
		array($id)
	);

	if (!cacti_sizeof($existing)) {
		restapi_error(404, 'not_found', "Section with ID $id not found");
		return;
	}

	$input = json_decode(file_get_contents('php://input'), true);

	if (!is_array($input)) {
		restapi_error(400, 'invalid_body', 'Request body must be valid JSON');
		return;
	}

	/* Build update fields — only update what was provided */
	$updates = array();
	$params  = array();

	if (isset($input['name'])) {
		$name = cereus_ipam_sanitize_text($input['name']);

		if ($name === '') {
			restapi_error(400, 'invalid_name', 'Section name cannot be empty');
			return;
		}

		$updates[] = 'name = ?';
		$params[]  = $name;
	}

	if (isset($input['parent_id'])) {
		$parent_id = intval($input['parent_id']);

		if ($parent_id > 0) {
			/* Prevent self-referencing */
			if ($parent_id == $id) {
				restapi_error(400, 'invalid_parent', 'A section cannot be its own parent');
				return;
			}

			$parent_exists = db_fetch_cell_prepared(
				'SELECT COUNT(*) FROM plugin_cereus_ipam_sections WHERE id = ?',
				array($parent_id)
			);

			if ($parent_exists == 0) {
				restapi_error(400, 'invalid_parent', "Parent section with ID $parent_id not found");
				return;
			}
		}

		$updates[] = 'parent_id = ?';
		$params[]  = ($parent_id > 0) ? $parent_id : null;
	}

	if (isset($input['description'])) {
		$updates[] = 'description = ?';
		$params[]  = cereus_ipam_sanitize_text($input['description']);
	}

	if (isset($input['permissions'])) {
		$updates[] = 'permissions = ?';
		$params[]  = cereus_ipam_sanitize_text($input['permissions']);
	}

	if (isset($input['display_order'])) {
		$updates[] = 'display_order = ?';
		$params[]  = intval($input['display_order']);
	}

	if (empty($updates)) {
		restapi_error(400, 'no_fields', 'No updatable fields provided');
		return;
	}

	$params[] = $id;

	db_execute_prepared(
		'UPDATE plugin_cereus_ipam_sections SET ' . implode(', ', $updates) . ' WHERE id = ?',
		$params
	);

	$updated = db_fetch_row_prepared(
		'SELECT id, parent_id, name, description, permissions, display_order, created, modified
		FROM plugin_cereus_ipam_sections
		WHERE id = ?',
		array($id)
	);

	cacti_log("RESTAPI IPAM: Section ID $id updated by user_id " . $context['user_id'], false, 'CEREUS_IPAM');

	cereus_ipam_changelog_record(
		CEREUS_IPAM_ACTION_UPDATE,
		CEREUS_IPAM_OBJ_SECTION,
		$id,
		$existing,
		$input
	);

	restapi_response($updated);
}

/**
 * Delete a section by ID.
 */
function cereus_ipam_restapi_delete_section($context) {
	$id = intval($context['id']);

	if ($id <= 0) {
		restapi_error(400, 'invalid_id', 'Invalid section ID');
		return;
	}

	$existing = db_fetch_row_prepared(
		'SELECT * FROM plugin_cereus_ipam_sections WHERE id = ?',
		array($id)
	);

	if (!cacti_sizeof($existing)) {
		restapi_error(404, 'not_found', "Section with ID $id not found");
		return;
	}

	/* Check if any subnets reference this section */
	$subnet_count = db_fetch_cell_prepared(
		'SELECT COUNT(*) FROM plugin_cereus_ipam_subnets WHERE section_id = ?',
		array($id)
	);

	if ($subnet_count > 0) {
		restapi_error(409, 'conflict', "Cannot delete section ID $id: $subnet_count subnet(s) still reference this section. Move or delete them first.");
		return;
	}

	db_execute_prepared(
		'DELETE FROM plugin_cereus_ipam_sections WHERE id = ?',
		array($id)
	);

	cacti_log("RESTAPI IPAM: Section ID $id deleted by user_id " . $context['user_id'], false, 'CEREUS_IPAM');

	cereus_ipam_changelog_record(
		CEREUS_IPAM_ACTION_DELETE,
		CEREUS_IPAM_OBJ_SECTION,
		$id,
		$existing,
		null
	);

	restapi_response(null, 204);
}

/* =========================================================================
 * Subnets Endpoint
 * ========================================================================= */

/**
 * GET    /ipam/subnets                    — List subnets (optional ?section_id=X filter)
 * GET    /ipam/subnets/{id}               — Get single subnet with utilization
 * GET    /ipam/subnets/{id}/addresses     — List addresses in subnet
 * GET    /ipam/subnets/{id}/first-free    — Next available IP
 * POST   /ipam/subnets                    — Create a new subnet
 * PUT    /ipam/subnets/{id}               — Update a subnet
 * DELETE /ipam/subnets/{id}               — Delete a subnet
 */
function cereus_ipam_restapi_subnets($context) {
	if (!cereus_ipam_license_has_restapi()) {
		restapi_error(403, 'license_required', 'IPAM REST API requires Enterprise license');
		return;
	}

	switch ($context['method']) {
		case 'GET':
			if ($context['id'] !== null) {
				if (!empty($context['sub_resource'])) {
					cereus_ipam_restapi_subnet_sub_resource($context);
				} else {
					cereus_ipam_restapi_get_subnet($context);
				}
			} else {
				cereus_ipam_restapi_list_subnets($context);
			}

			break;

		case 'POST':
			if ($context['id'] !== null) {
				restapi_error(400, 'invalid_request', 'POST to a specific subnet ID is not supported');
				return;
			}

			cereus_ipam_restapi_create_subnet($context);

			break;

		case 'PUT':
			if ($context['id'] === null) {
				restapi_error(400, 'missing_id', 'Subnet ID is required for updates');
				return;
			}

			cereus_ipam_restapi_update_subnet($context);

			break;

		case 'DELETE':
			if ($context['id'] === null) {
				restapi_error(400, 'missing_id', 'Subnet ID is required for deletion');
				return;
			}

			cereus_ipam_restapi_delete_subnet($context);

			break;

		default:
			restapi_error(405, 'method_not_allowed', 'Supported methods: GET, POST, PUT, DELETE');
	}
}

/**
 * List subnets with optional section_id filter.
 */
function cereus_ipam_restapi_list_subnets($context) {
	$where  = '';
	$params = array();

	$section_id = isset($_GET['section_id']) ? intval($_GET['section_id']) : 0;

	if ($section_id > 0) {
		$where  = 'WHERE s.section_id = ?';
		$params = array($section_id);
	}

	$subnets = db_fetch_assoc_prepared(
		"SELECT s.id, s.section_id, s.parent_id, s.subnet, s.mask, s.description,
			s.gateway, s.vlan_id, s.vrf_id, s.nameservers, s.threshold_pct,
			s.scan_enabled, s.scan_interval, s.last_scanned, s.show_name,
			s.is_pool, s.created, s.modified,
			sec.name AS section_name
		FROM plugin_cereus_ipam_subnets AS s
		LEFT JOIN plugin_cereus_ipam_sections AS sec ON s.section_id = sec.id
		$where
		ORDER BY s.subnet, s.mask",
		$params
	);

	if (!is_array($subnets)) {
		$subnets = array();
	}

	restapi_response($subnets);
}

/**
 * Get a single subnet by ID with utilization stats.
 */
function cereus_ipam_restapi_get_subnet($context) {
	$id = intval($context['id']);

	if ($id <= 0) {
		restapi_error(400, 'invalid_id', 'Invalid subnet ID');
		return;
	}

	$subnet = db_fetch_row_prepared(
		"SELECT s.id, s.section_id, s.parent_id, s.subnet, s.mask, s.description,
			s.gateway, s.vlan_id, s.vrf_id, s.nameservers, s.threshold_pct,
			s.scan_enabled, s.scan_interval, s.last_scanned, s.show_name,
			s.is_pool, s.created, s.modified,
			sec.name AS section_name
		FROM plugin_cereus_ipam_subnets AS s
		LEFT JOIN plugin_cereus_ipam_sections AS sec ON s.section_id = sec.id
		WHERE s.id = ?",
		array($id)
	);

	if (!cacti_sizeof($subnet)) {
		restapi_error(404, 'not_found', "Subnet with ID $id not found");
		return;
	}

	$subnet['utilization'] = cereus_ipam_subnet_utilization($id);

	restapi_response($subnet);
}

/**
 * Handle subnet sub-resources: addresses, first-free.
 */
function cereus_ipam_restapi_subnet_sub_resource($context) {
	$id = intval($context['id']);

	if ($id <= 0) {
		restapi_error(400, 'invalid_id', 'Invalid subnet ID');
		return;
	}

	/* Verify subnet exists */
	$exists = db_fetch_cell_prepared(
		'SELECT COUNT(*) FROM plugin_cereus_ipam_subnets WHERE id = ?',
		array($id)
	);

	if ($exists == 0) {
		restapi_error(404, 'not_found', "Subnet with ID $id not found");
		return;
	}

	switch ($context['sub_resource']) {
		case 'addresses':
			$addresses = db_fetch_assoc_prepared(
				"SELECT id, subnet_id, ip, hostname, description, mac_address, owner,
					device_type, device_location, state, cacti_host_id,
					nat_inside, nat_outside, last_seen, port, note,
					created_by, created, modified
				FROM plugin_cereus_ipam_addresses
				WHERE subnet_id = ?
				ORDER BY INET_ATON(ip)",
				array($id)
			);

			if (!is_array($addresses)) {
				$addresses = array();
			}

			restapi_response($addresses);

			break;

		case 'first-free':
			$next_ip = cereus_ipam_next_available($id);

			if ($next_ip === false) {
				restapi_error(404, 'subnet_full', "No available IP addresses in subnet $id");
				return;
			}

			restapi_response(array('next_available' => $next_ip, 'subnet_id' => $id));

			break;

		default:
			restapi_error(404, 'sub_resource_not_found',
				"Sub-resource '" . $context['sub_resource'] . "' not found for subnets");
	}
}

/**
 * Create a new subnet.
 */
function cereus_ipam_restapi_create_subnet($context) {
	$input = json_decode(file_get_contents('php://input'), true);

	if (!is_array($input)) {
		restapi_error(400, 'invalid_body', 'Request body must be valid JSON');
		return;
	}

	/* Required fields */
	if (empty($input['section_id']) || empty($input['subnet']) || !isset($input['mask'])) {
		restapi_error(400, 'missing_fields', 'Fields section_id, subnet, and mask are required');
		return;
	}

	$section_id    = intval($input['section_id']);
	$subnet_addr   = trim($input['subnet']);
	$mask          = intval($input['mask']);
	$description   = isset($input['description'])   ? cereus_ipam_sanitize_text($input['description'])   : '';
	$gateway       = isset($input['gateway'])        ? trim($input['gateway'])                            : null;
	$vlan_id       = isset($input['vlan_id'])        ? intval($input['vlan_id'])                          : null;
	$vrf_id        = isset($input['vrf_id'])         ? intval($input['vrf_id'])                           : null;
	$threshold_pct = isset($input['threshold_pct'])  ? intval($input['threshold_pct'])                    : 90;

	/* Validate section exists */
	$section_exists = db_fetch_cell_prepared(
		'SELECT COUNT(*) FROM plugin_cereus_ipam_sections WHERE id = ?',
		array($section_id)
	);

	if ($section_exists == 0) {
		restapi_error(400, 'invalid_section', "Section with ID $section_id not found");
		return;
	}

	/* Validate IP address */
	if (!cereus_ipam_validate_ip($subnet_addr)) {
		restapi_error(400, 'invalid_ip', "Invalid subnet address: $subnet_addr");
		return;
	}

	/* Validate CIDR mask */
	$version = cereus_ipam_ip_version($subnet_addr);

	if (!cereus_ipam_validate_cidr($mask, $version)) {
		restapi_error(400, 'invalid_cidr', "Invalid CIDR mask: $mask for IPv$version");
		return;
	}

	/* Validate that the address is a proper network address */
	if (!cereus_ipam_validate_subnet($subnet_addr, $mask)) {
		$network = cereus_ipam_network_address($subnet_addr, $mask);
		restapi_error(400, 'invalid_network', "Address $subnet_addr is not a valid network address for /$mask. Did you mean $network?");
		return;
	}

	/* Validate gateway if provided */
	if ($gateway !== null && $gateway !== '' && !cereus_ipam_validate_ip($gateway)) {
		restapi_error(400, 'invalid_gateway', "Invalid gateway address: $gateway");
		return;
	}

	/* Validate threshold range */
	if ($threshold_pct < 0 || $threshold_pct > 100) {
		restapi_error(400, 'invalid_threshold', 'Threshold percentage must be between 0 and 100');
		return;
	}

	/* Check for duplicate subnet in same section */
	$duplicate = db_fetch_cell_prepared(
		'SELECT COUNT(*) FROM plugin_cereus_ipam_subnets WHERE section_id = ? AND subnet = ? AND mask = ?',
		array($section_id, $subnet_addr, $mask)
	);

	if ($duplicate > 0) {
		restapi_error(409, 'duplicate_subnet', "Subnet $subnet_addr/$mask already exists in section $section_id");
		return;
	}

	/* Check community subnet limit */
	$max_subnets = cereus_ipam_license_max_subnets();

	if ($max_subnets > 0) {
		$current_count = cereus_ipam_license_subnet_count();

		if ($current_count >= $max_subnets) {
			restapi_error(403, 'limit_reached', "Maximum subnet limit ($max_subnets) reached for current license tier");
			return;
		}
	}

	db_execute_prepared(
		"INSERT INTO plugin_cereus_ipam_subnets
			(section_id, subnet, mask, description, gateway, vlan_id, vrf_id, threshold_pct)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		array($section_id, $subnet_addr, $mask, $description, $gateway, $vlan_id, $vrf_id, $threshold_pct)
	);

	$new_id = db_fetch_insert_id();

	if (empty($new_id)) {
		restapi_error(500, 'create_failed', 'Failed to create subnet');
		return;
	}

	$created = db_fetch_row_prepared(
		"SELECT s.*, sec.name AS section_name
		FROM plugin_cereus_ipam_subnets AS s
		LEFT JOIN plugin_cereus_ipam_sections AS sec ON s.section_id = sec.id
		WHERE s.id = ?",
		array($new_id)
	);

	cacti_log("RESTAPI IPAM: Subnet $subnet_addr/$mask created (ID: $new_id) by user_id " . $context['user_id'], false, 'CEREUS_IPAM');

	cereus_ipam_changelog_record(
		CEREUS_IPAM_ACTION_CREATE,
		CEREUS_IPAM_OBJ_SUBNET,
		$new_id,
		null,
		$input
	);

	restapi_response($created, 201);
}

/**
 * Update an existing subnet.
 */
function cereus_ipam_restapi_update_subnet($context) {
	$id = intval($context['id']);

	if ($id <= 0) {
		restapi_error(400, 'invalid_id', 'Invalid subnet ID');
		return;
	}

	$existing = db_fetch_row_prepared(
		'SELECT * FROM plugin_cereus_ipam_subnets WHERE id = ?',
		array($id)
	);

	if (!cacti_sizeof($existing)) {
		restapi_error(404, 'not_found', "Subnet with ID $id not found");
		return;
	}

	$input = json_decode(file_get_contents('php://input'), true);

	if (!is_array($input)) {
		restapi_error(400, 'invalid_body', 'Request body must be valid JSON');
		return;
	}

	/* Build update fields — only update what was provided */
	$updates = array();
	$params  = array();

	if (isset($input['section_id'])) {
		$section_id = intval($input['section_id']);

		$section_exists = db_fetch_cell_prepared(
			'SELECT COUNT(*) FROM plugin_cereus_ipam_sections WHERE id = ?',
			array($section_id)
		);

		if ($section_exists == 0) {
			restapi_error(400, 'invalid_section', "Section with ID $section_id not found");
			return;
		}

		$updates[] = 'section_id = ?';
		$params[]  = $section_id;
	}

	/* Track subnet/mask changes for later validation */
	$new_subnet_addr = isset($input['subnet']) ? trim($input['subnet']) : null;
	$new_mask        = isset($input['mask'])   ? intval($input['mask']) : null;

	if ($new_subnet_addr !== null || $new_mask !== null) {
		$check_addr = ($new_subnet_addr !== null) ? $new_subnet_addr : $existing['subnet'];
		$check_mask = ($new_mask !== null)         ? $new_mask        : intval($existing['mask']);

		/* Validate IP address */
		if (!cereus_ipam_validate_ip($check_addr)) {
			restapi_error(400, 'invalid_ip', "Invalid subnet address: $check_addr");
			return;
		}

		/* Validate CIDR mask */
		$version = cereus_ipam_ip_version($check_addr);

		if (!cereus_ipam_validate_cidr($check_mask, $version)) {
			restapi_error(400, 'invalid_cidr', "Invalid CIDR mask: $check_mask for IPv$version");
			return;
		}

		/* Validate that the address is a proper network address */
		if (!cereus_ipam_validate_subnet($check_addr, $check_mask)) {
			$network = cereus_ipam_network_address($check_addr, $check_mask);
			restapi_error(400, 'invalid_network', "Address $check_addr is not a valid network address for /$check_mask. Did you mean $network?");
			return;
		}

		/* Check for duplicate subnet in same section */
		$check_section = isset($input['section_id']) ? intval($input['section_id']) : intval($existing['section_id']);

		$duplicate = db_fetch_cell_prepared(
			'SELECT COUNT(*) FROM plugin_cereus_ipam_subnets WHERE section_id = ? AND subnet = ? AND mask = ? AND id != ?',
			array($check_section, $check_addr, $check_mask, $id)
		);

		if ($duplicate > 0) {
			restapi_error(409, 'duplicate_subnet', "Subnet $check_addr/$check_mask already exists in section $check_section");
			return;
		}

		if ($new_subnet_addr !== null) {
			$updates[] = 'subnet = ?';
			$params[]  = $check_addr;
		}

		if ($new_mask !== null) {
			$updates[] = 'mask = ?';
			$params[]  = $check_mask;
		}
	}

	if (isset($input['description'])) {
		$updates[] = 'description = ?';
		$params[]  = cereus_ipam_sanitize_text($input['description']);
	}

	if (isset($input['gateway'])) {
		$gw = trim($input['gateway']);

		if ($gw !== '' && !cereus_ipam_validate_ip($gw)) {
			restapi_error(400, 'invalid_gateway', "Invalid gateway address: $gw");
			return;
		}

		$updates[] = 'gateway = ?';
		$params[]  = ($gw !== '') ? $gw : null;
	}

	if (isset($input['vlan_id'])) {
		$updates[] = 'vlan_id = ?';
		$params[]  = ($input['vlan_id'] !== null && $input['vlan_id'] !== '') ? intval($input['vlan_id']) : null;
	}

	if (isset($input['vrf_id'])) {
		$updates[] = 'vrf_id = ?';
		$params[]  = ($input['vrf_id'] !== null && $input['vrf_id'] !== '') ? intval($input['vrf_id']) : null;
	}

	if (isset($input['threshold_pct'])) {
		$threshold = intval($input['threshold_pct']);

		if ($threshold < 0 || $threshold > 100) {
			restapi_error(400, 'invalid_threshold', 'Threshold percentage must be between 0 and 100');
			return;
		}

		$updates[] = 'threshold_pct = ?';
		$params[]  = $threshold;
	}

	if (isset($input['nameservers'])) {
		$updates[] = 'nameservers = ?';
		$params[]  = cereus_ipam_sanitize_text($input['nameservers']);
	}

	if (isset($input['scan_enabled'])) {
		$updates[] = 'scan_enabled = ?';
		$params[]  = intval($input['scan_enabled']) ? 1 : 0;
	}

	if (isset($input['scan_interval'])) {
		$updates[] = 'scan_interval = ?';
		$params[]  = intval($input['scan_interval']);
	}

	if (isset($input['show_name'])) {
		$updates[] = 'show_name = ?';
		$params[]  = intval($input['show_name']) ? 1 : 0;
	}

	if (isset($input['is_pool'])) {
		$updates[] = 'is_pool = ?';
		$params[]  = intval($input['is_pool']) ? 1 : 0;
	}

	if (empty($updates)) {
		restapi_error(400, 'no_fields', 'No updatable fields provided');
		return;
	}

	$params[] = $id;

	db_execute_prepared(
		'UPDATE plugin_cereus_ipam_subnets SET ' . implode(', ', $updates) . ' WHERE id = ?',
		$params
	);

	$updated = db_fetch_row_prepared(
		"SELECT s.*, sec.name AS section_name
		FROM plugin_cereus_ipam_subnets AS s
		LEFT JOIN plugin_cereus_ipam_sections AS sec ON s.section_id = sec.id
		WHERE s.id = ?",
		array($id)
	);

	cacti_log("RESTAPI IPAM: Subnet ID $id updated by user_id " . $context['user_id'], false, 'CEREUS_IPAM');

	cereus_ipam_changelog_record(
		CEREUS_IPAM_ACTION_UPDATE,
		CEREUS_IPAM_OBJ_SUBNET,
		$id,
		$existing,
		$input
	);

	restapi_response($updated);
}

/**
 * Delete a subnet by ID (also deletes all addresses within it).
 */
function cereus_ipam_restapi_delete_subnet($context) {
	$id = intval($context['id']);

	if ($id <= 0) {
		restapi_error(400, 'invalid_id', 'Invalid subnet ID');
		return;
	}

	$existing = db_fetch_row_prepared(
		'SELECT * FROM plugin_cereus_ipam_subnets WHERE id = ?',
		array($id)
	);

	if (!cacti_sizeof($existing)) {
		restapi_error(404, 'not_found', "Subnet with ID $id not found");
		return;
	}

	/* Check if subnet has addresses — warn but still delete */
	$address_count = db_fetch_cell_prepared(
		'SELECT COUNT(*) FROM plugin_cereus_ipam_addresses WHERE subnet_id = ?',
		array($id)
	);

	/* Delete all addresses in this subnet first */
	if ($address_count > 0) {
		db_execute_prepared(
			'DELETE FROM plugin_cereus_ipam_addresses WHERE subnet_id = ?',
			array($id)
		);

		cacti_log("RESTAPI IPAM: Deleted $address_count address(es) from subnet ID $id (cascade) by user_id " . $context['user_id'], false, 'CEREUS_IPAM');
	}

	/* Delete the subnet */
	db_execute_prepared(
		'DELETE FROM plugin_cereus_ipam_subnets WHERE id = ?',
		array($id)
	);

	cacti_log("RESTAPI IPAM: Subnet ID $id (" . $existing['subnet'] . '/' . $existing['mask'] . ") deleted by user_id " . $context['user_id'] . ($address_count > 0 ? " ($address_count addresses also removed)" : ''), false, 'CEREUS_IPAM');

	cereus_ipam_changelog_record(
		CEREUS_IPAM_ACTION_DELETE,
		CEREUS_IPAM_OBJ_SUBNET,
		$id,
		$existing,
		null
	);

	restapi_response(null, 204);
}

/* =========================================================================
 * Addresses Endpoint
 * ========================================================================= */

/**
 * GET    /ipam/addresses/{id}  — Get single address
 * POST   /ipam/addresses       — Create address
 * PUT    /ipam/addresses/{id}  — Update address
 * DELETE /ipam/addresses/{id}  — Delete address
 */
function cereus_ipam_restapi_addresses($context) {
	if (!cereus_ipam_license_has_restapi()) {
		restapi_error(403, 'license_required', 'IPAM REST API requires Enterprise license');
		return;
	}

	switch ($context['method']) {
		case 'GET':
			if ($context['id'] === null) {
				restapi_error(400, 'missing_id', 'Address ID is required for GET. Use /ipam/subnets/{id}/addresses to list.');
				return;
			}

			cereus_ipam_restapi_get_address($context);

			break;

		case 'POST':
			cereus_ipam_restapi_create_address($context);

			break;

		case 'PUT':
			if ($context['id'] === null) {
				restapi_error(400, 'missing_id', 'Address ID is required for updates');
				return;
			}

			cereus_ipam_restapi_update_address($context);

			break;

		case 'DELETE':
			if ($context['id'] === null) {
				restapi_error(400, 'missing_id', 'Address ID is required for deletion');
				return;
			}

			cereus_ipam_restapi_delete_address($context);

			break;

		default:
			restapi_error(405, 'method_not_allowed', 'Supported methods: GET, POST, PUT, DELETE');
	}
}

/**
 * Get a single address by ID.
 */
function cereus_ipam_restapi_get_address($context) {
	$id = intval($context['id']);

	if ($id <= 0) {
		restapi_error(400, 'invalid_id', 'Invalid address ID');
		return;
	}

	$address = db_fetch_row_prepared(
		"SELECT a.id, a.subnet_id, a.ip, a.hostname, a.description, a.mac_address,
			a.owner, a.device_type, a.device_location, a.state, a.cacti_host_id,
			a.nat_inside, a.nat_outside, a.last_seen, a.port, a.note,
			a.created_by, a.created, a.modified,
			s.subnet AS subnet_addr, s.mask AS subnet_mask
		FROM plugin_cereus_ipam_addresses AS a
		LEFT JOIN plugin_cereus_ipam_subnets AS s ON a.subnet_id = s.id
		WHERE a.id = ?",
		array($id)
	);

	if (!cacti_sizeof($address)) {
		restapi_error(404, 'not_found', "Address with ID $id not found");
		return;
	}

	restapi_response($address);
}

/**
 * Create a new address.
 */
function cereus_ipam_restapi_create_address($context) {
	$input = json_decode(file_get_contents('php://input'), true);

	if (!is_array($input)) {
		restapi_error(400, 'invalid_body', 'Request body must be valid JSON');
		return;
	}

	/* Required fields */
	if (empty($input['subnet_id']) || empty($input['ip'])) {
		restapi_error(400, 'missing_fields', 'Fields subnet_id and ip are required');
		return;
	}

	$subnet_id   = intval($input['subnet_id']);
	$ip          = trim($input['ip']);
	$hostname    = isset($input['hostname'])    ? cereus_ipam_sanitize_text($input['hostname'])    : null;
	$description = isset($input['description']) ? cereus_ipam_sanitize_text($input['description']) : null;
	$state       = isset($input['state'])       ? trim($input['state'])                            : 'active';
	$mac_address = isset($input['mac_address']) ? trim($input['mac_address'])                      : null;
	$owner       = isset($input['owner'])       ? cereus_ipam_sanitize_text($input['owner'])       : null;
	$device_type = isset($input['device_type']) ? cereus_ipam_sanitize_text($input['device_type']) : null;

	/* Validate subnet exists */
	$subnet = db_fetch_row_prepared(
		'SELECT id, subnet, mask FROM plugin_cereus_ipam_subnets WHERE id = ?',
		array($subnet_id)
	);

	if (!cacti_sizeof($subnet)) {
		restapi_error(400, 'invalid_subnet', "Subnet with ID $subnet_id not found");
		return;
	}

	/* Validate IP address */
	if (!cereus_ipam_validate_ip($ip)) {
		restapi_error(400, 'invalid_ip', "Invalid IP address: $ip");
		return;
	}

	/* Validate IP belongs to subnet */
	if (!cereus_ipam_ip_in_subnet($ip, $subnet['subnet'], $subnet['mask'])) {
		restapi_error(400, 'ip_not_in_subnet', "IP $ip does not belong to subnet " . $subnet['subnet'] . '/' . $subnet['mask']);
		return;
	}

	/* Validate state */
	if (!cereus_ipam_validate_state($state)) {
		restapi_error(400, 'invalid_state', "Invalid state '$state'. Allowed: active, reserved, dhcp, offline, available");
		return;
	}

	/* Validate MAC address if provided */
	if ($mac_address !== null && $mac_address !== '') {
		$normalized_mac = cereus_ipam_normalize_mac($mac_address);

		if ($normalized_mac === false) {
			restapi_error(400, 'invalid_mac', "Invalid MAC address format: $mac_address");
			return;
		}

		$mac_address = $normalized_mac;
	}

	/* Check for duplicate IP in same subnet */
	$duplicate = db_fetch_cell_prepared(
		'SELECT COUNT(*) FROM plugin_cereus_ipam_addresses WHERE subnet_id = ? AND ip = ?',
		array($subnet_id, $ip)
	);

	if ($duplicate > 0) {
		restapi_error(409, 'duplicate_address', "IP $ip already exists in subnet $subnet_id");
		return;
	}

	db_execute_prepared(
		"INSERT INTO plugin_cereus_ipam_addresses
			(subnet_id, ip, hostname, description, state, mac_address, owner, device_type, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		array($subnet_id, $ip, $hostname, $description, $state, $mac_address, $owner, $device_type, $context['user_id'])
	);

	$new_id = db_fetch_insert_id();

	if (empty($new_id)) {
		restapi_error(500, 'create_failed', 'Failed to create address');
		return;
	}

	$created = db_fetch_row_prepared(
		'SELECT * FROM plugin_cereus_ipam_addresses WHERE id = ?',
		array($new_id)
	);

	cacti_log("RESTAPI IPAM: Address $ip created (ID: $new_id) in subnet $subnet_id by user_id " . $context['user_id'], false, 'CEREUS_IPAM');

	cereus_ipam_changelog_record(
		CEREUS_IPAM_ACTION_CREATE,
		CEREUS_IPAM_OBJ_ADDRESS,
		$new_id,
		null,
		$input
	);

	restapi_response($created, 201);
}

/**
 * Update an existing address.
 */
function cereus_ipam_restapi_update_address($context) {
	$id = intval($context['id']);

	if ($id <= 0) {
		restapi_error(400, 'invalid_id', 'Invalid address ID');
		return;
	}

	$existing = db_fetch_row_prepared(
		'SELECT * FROM plugin_cereus_ipam_addresses WHERE id = ?',
		array($id)
	);

	if (!cacti_sizeof($existing)) {
		restapi_error(404, 'not_found', "Address with ID $id not found");
		return;
	}

	$input = json_decode(file_get_contents('php://input'), true);

	if (!is_array($input)) {
		restapi_error(400, 'invalid_body', 'Request body must be valid JSON');
		return;
	}

	/* Build update fields — only update what was provided */
	$updates = array();
	$params  = array();

	if (isset($input['hostname'])) {
		$updates[]  = 'hostname = ?';
		$params[]   = cereus_ipam_sanitize_text($input['hostname']);
	}

	if (isset($input['description'])) {
		$updates[]  = 'description = ?';
		$params[]   = cereus_ipam_sanitize_text($input['description']);
	}

	if (isset($input['state'])) {
		$state = trim($input['state']);

		if (!cereus_ipam_validate_state($state)) {
			restapi_error(400, 'invalid_state', "Invalid state '$state'. Allowed: active, reserved, dhcp, offline, available");
			return;
		}

		$updates[] = 'state = ?';
		$params[]  = $state;
	}

	if (isset($input['mac_address'])) {
		$mac = trim($input['mac_address']);

		if ($mac !== '') {
			$normalized_mac = cereus_ipam_normalize_mac($mac);

			if ($normalized_mac === false) {
				restapi_error(400, 'invalid_mac', "Invalid MAC address format: $mac");
				return;
			}

			$mac = $normalized_mac;
		}

		$updates[] = 'mac_address = ?';
		$params[]  = ($mac !== '') ? $mac : null;
	}

	if (isset($input['owner'])) {
		$updates[] = 'owner = ?';
		$params[]  = cereus_ipam_sanitize_text($input['owner']);
	}

	if (isset($input['device_type'])) {
		$updates[] = 'device_type = ?';
		$params[]  = cereus_ipam_sanitize_text($input['device_type']);
	}

	if (isset($input['device_location'])) {
		$updates[] = 'device_location = ?';
		$params[]  = cereus_ipam_sanitize_text($input['device_location']);
	}

	if (isset($input['port'])) {
		$updates[] = 'port = ?';
		$params[]  = cereus_ipam_sanitize_text($input['port'], 64);
	}

	if (isset($input['note'])) {
		$updates[] = 'note = ?';
		$params[]  = cereus_ipam_sanitize_text($input['note'], 65535);
	}

	if (isset($input['ip'])) {
		$new_ip = trim($input['ip']);

		if (!cereus_ipam_validate_ip($new_ip)) {
			restapi_error(400, 'invalid_ip', "Invalid IP address: $new_ip");
			return;
		}

		/* Validate new IP belongs to the same subnet */
		$subnet = db_fetch_row_prepared(
			'SELECT subnet, mask FROM plugin_cereus_ipam_subnets WHERE id = ?',
			array($existing['subnet_id'])
		);

		if (cacti_sizeof($subnet) && !cereus_ipam_ip_in_subnet($new_ip, $subnet['subnet'], $subnet['mask'])) {
			restapi_error(400, 'ip_not_in_subnet', "IP $new_ip does not belong to subnet " . $subnet['subnet'] . '/' . $subnet['mask']);
			return;
		}

		/* Check for duplicate */
		$dup = db_fetch_cell_prepared(
			'SELECT COUNT(*) FROM plugin_cereus_ipam_addresses WHERE subnet_id = ? AND ip = ? AND id != ?',
			array($existing['subnet_id'], $new_ip, $id)
		);

		if ($dup > 0) {
			restapi_error(409, 'duplicate_address', "IP $new_ip already exists in subnet " . $existing['subnet_id']);
			return;
		}

		$updates[] = 'ip = ?';
		$params[]  = $new_ip;
	}

	if (empty($updates)) {
		restapi_error(400, 'no_fields', 'No updatable fields provided');
		return;
	}

	$params[] = $id;

	db_execute_prepared(
		'UPDATE plugin_cereus_ipam_addresses SET ' . implode(', ', $updates) . ' WHERE id = ?',
		$params
	);

	$updated = db_fetch_row_prepared(
		'SELECT * FROM plugin_cereus_ipam_addresses WHERE id = ?',
		array($id)
	);

	cacti_log("RESTAPI IPAM: Address ID $id updated by user_id " . $context['user_id'], false, 'CEREUS_IPAM');

	cereus_ipam_changelog_record(
		CEREUS_IPAM_ACTION_UPDATE,
		CEREUS_IPAM_OBJ_ADDRESS,
		$id,
		$existing,
		$input
	);

	restapi_response($updated);
}

/**
 * Delete an address by ID.
 */
function cereus_ipam_restapi_delete_address($context) {
	$id = intval($context['id']);

	if ($id <= 0) {
		restapi_error(400, 'invalid_id', 'Invalid address ID');
		return;
	}

	$existing = db_fetch_row_prepared(
		'SELECT * FROM plugin_cereus_ipam_addresses WHERE id = ?',
		array($id)
	);

	if (!cacti_sizeof($existing)) {
		restapi_error(404, 'not_found', "Address with ID $id not found");
		return;
	}

	db_execute_prepared(
		'DELETE FROM plugin_cereus_ipam_addresses WHERE id = ?',
		array($id)
	);

	cacti_log("RESTAPI IPAM: Address ID $id deleted by user_id " . $context['user_id'], false, 'CEREUS_IPAM');

	cereus_ipam_changelog_record(
		CEREUS_IPAM_ACTION_DELETE,
		CEREUS_IPAM_OBJ_ADDRESS,
		$id,
		$existing,
		null
	);

	restapi_response(null, 204);
}

/* =========================================================================
 * VLANs Endpoint
 * ========================================================================= */

/**
 * GET    /ipam/vlans         — List all VLANs
 * GET    /ipam/vlans/{id}    — Get single VLAN
 * POST   /ipam/vlans         — Create VLAN
 * PUT    /ipam/vlans/{id}    — Update VLAN
 * DELETE /ipam/vlans/{id}    — Delete VLAN
 */
function cereus_ipam_restapi_vlans($context) {
	if (!cereus_ipam_license_has_restapi()) {
		restapi_error(403, 'license_required', 'IPAM REST API requires Enterprise license');
		return;
	}

	switch ($context['method']) {
		case 'GET':
			if ($context['id'] !== null) {
				cereus_ipam_restapi_get_vlan($context);
			} else {
				cereus_ipam_restapi_list_vlans($context);
			}

			break;

		case 'POST':
			if ($context['id'] !== null) {
				restapi_error(400, 'invalid_request', 'POST to a specific VLAN ID is not supported');
				return;
			}

			cereus_ipam_restapi_create_vlan($context);

			break;

		case 'PUT':
			if ($context['id'] === null) {
				restapi_error(400, 'missing_id', 'VLAN ID is required for updates');
				return;
			}

			cereus_ipam_restapi_update_vlan($context);

			break;

		case 'DELETE':
			if ($context['id'] === null) {
				restapi_error(400, 'missing_id', 'VLAN ID is required for deletion');
				return;
			}

			cereus_ipam_restapi_delete_vlan($context);

			break;

		default:
			restapi_error(405, 'method_not_allowed', 'Supported methods: GET, POST, PUT, DELETE');
	}
}

/**
 * List all VLANs.
 */
function cereus_ipam_restapi_list_vlans($context) {
	$vlans = db_fetch_assoc_prepared(
		'SELECT id, vlan_number, name, description, domain_id, created, modified
		FROM plugin_cereus_ipam_vlans
		ORDER BY vlan_number',
		array()
	);

	if (!is_array($vlans)) {
		$vlans = array();
	}

	restapi_response($vlans);
}

/**
 * Get a single VLAN by ID.
 */
function cereus_ipam_restapi_get_vlan($context) {
	$id = intval($context['id']);

	if ($id <= 0) {
		restapi_error(400, 'invalid_id', 'Invalid VLAN ID');
		return;
	}

	$vlan = db_fetch_row_prepared(
		'SELECT id, vlan_number, name, description, domain_id, created, modified
		FROM plugin_cereus_ipam_vlans
		WHERE id = ?',
		array($id)
	);

	if (!cacti_sizeof($vlan)) {
		restapi_error(404, 'not_found', "VLAN with ID $id not found");
		return;
	}

	restapi_response($vlan);
}

/**
 * Create a new VLAN.
 */
function cereus_ipam_restapi_create_vlan($context) {
	$input = json_decode(file_get_contents('php://input'), true);

	if (!is_array($input)) {
		restapi_error(400, 'invalid_body', 'Request body must be valid JSON');
		return;
	}

	/* Required fields */
	if (!isset($input['vlan_number']) || empty($input['name'])) {
		restapi_error(400, 'missing_fields', 'Fields vlan_number and name are required');
		return;
	}

	$vlan_number = intval($input['vlan_number']);
	$name        = cereus_ipam_sanitize_text($input['name']);
	$description = isset($input['description']) ? cereus_ipam_sanitize_text($input['description']) : '';
	$domain_id   = isset($input['domain_id'])   ? intval($input['domain_id'])                      : null;

	/* Validate VLAN number (1-4094) */
	if (!cereus_ipam_validate_vlan($vlan_number)) {
		restapi_error(400, 'invalid_vlan_number', "VLAN number must be between 1 and 4094, got: $vlan_number");
		return;
	}

	/* Validate name not empty after sanitization */
	if ($name === '') {
		restapi_error(400, 'invalid_name', 'VLAN name cannot be empty');
		return;
	}

	/* Check for duplicate (domain_id + vlan_number) */
	if ($domain_id !== null && $domain_id > 0) {
		$duplicate = db_fetch_cell_prepared(
			'SELECT COUNT(*) FROM plugin_cereus_ipam_vlans WHERE domain_id = ? AND vlan_number = ?',
			array($domain_id, $vlan_number)
		);
	} else {
		$duplicate = db_fetch_cell_prepared(
			'SELECT COUNT(*) FROM plugin_cereus_ipam_vlans WHERE (domain_id IS NULL OR domain_id = 0) AND vlan_number = ?',
			array($vlan_number)
		);
	}

	if ($duplicate > 0) {
		restapi_error(409, 'duplicate_vlan', "VLAN $vlan_number already exists in the specified domain");
		return;
	}

	db_execute_prepared(
		"INSERT INTO plugin_cereus_ipam_vlans
			(vlan_number, name, description, domain_id)
		VALUES (?, ?, ?, ?)",
		array($vlan_number, $name, $description, $domain_id)
	);

	$new_id = db_fetch_insert_id();

	if (empty($new_id)) {
		restapi_error(500, 'create_failed', 'Failed to create VLAN');
		return;
	}

	$created = db_fetch_row_prepared(
		'SELECT id, vlan_number, name, description, domain_id, created, modified
		FROM plugin_cereus_ipam_vlans
		WHERE id = ?',
		array($new_id)
	);

	cacti_log("RESTAPI IPAM: VLAN $vlan_number '$name' created (ID: $new_id) by user_id " . $context['user_id'], false, 'CEREUS_IPAM');

	cereus_ipam_changelog_record(
		CEREUS_IPAM_ACTION_CREATE,
		CEREUS_IPAM_OBJ_VLAN,
		$new_id,
		null,
		$input
	);

	restapi_response($created, 201);
}

/**
 * Update an existing VLAN.
 */
function cereus_ipam_restapi_update_vlan($context) {
	$id = intval($context['id']);

	if ($id <= 0) {
		restapi_error(400, 'invalid_id', 'Invalid VLAN ID');
		return;
	}

	$existing = db_fetch_row_prepared(
		'SELECT * FROM plugin_cereus_ipam_vlans WHERE id = ?',
		array($id)
	);

	if (!cacti_sizeof($existing)) {
		restapi_error(404, 'not_found', "VLAN with ID $id not found");
		return;
	}

	$input = json_decode(file_get_contents('php://input'), true);

	if (!is_array($input)) {
		restapi_error(400, 'invalid_body', 'Request body must be valid JSON');
		return;
	}

	/* Build update fields — only update what was provided */
	$updates = array();
	$params  = array();

	$check_vlan_number = isset($input['vlan_number']) ? intval($input['vlan_number']) : null;
	$check_domain_id   = isset($input['domain_id'])   ? intval($input['domain_id'])   : null;

	if ($check_vlan_number !== null) {
		if (!cereus_ipam_validate_vlan($check_vlan_number)) {
			restapi_error(400, 'invalid_vlan_number', "VLAN number must be between 1 and 4094, got: $check_vlan_number");
			return;
		}
	}

	/* Check for duplicate if vlan_number or domain_id changed */
	if ($check_vlan_number !== null || $check_domain_id !== null) {
		$dup_vlan   = ($check_vlan_number !== null) ? $check_vlan_number : intval($existing['vlan_number']);
		$dup_domain = ($check_domain_id !== null)   ? $check_domain_id   : $existing['domain_id'];

		if ($dup_domain !== null && $dup_domain > 0) {
			$duplicate = db_fetch_cell_prepared(
				'SELECT COUNT(*) FROM plugin_cereus_ipam_vlans WHERE domain_id = ? AND vlan_number = ? AND id != ?',
				array($dup_domain, $dup_vlan, $id)
			);
		} else {
			$duplicate = db_fetch_cell_prepared(
				'SELECT COUNT(*) FROM plugin_cereus_ipam_vlans WHERE (domain_id IS NULL OR domain_id = 0) AND vlan_number = ? AND id != ?',
				array($dup_vlan, $id)
			);
		}

		if ($duplicate > 0) {
			restapi_error(409, 'duplicate_vlan', "VLAN $dup_vlan already exists in the specified domain");
			return;
		}
	}

	if ($check_vlan_number !== null) {
		$updates[] = 'vlan_number = ?';
		$params[]  = $check_vlan_number;
	}

	if (isset($input['name'])) {
		$name = cereus_ipam_sanitize_text($input['name']);

		if ($name === '') {
			restapi_error(400, 'invalid_name', 'VLAN name cannot be empty');
			return;
		}

		$updates[] = 'name = ?';
		$params[]  = $name;
	}

	if (isset($input['description'])) {
		$updates[] = 'description = ?';
		$params[]  = cereus_ipam_sanitize_text($input['description']);
	}

	if ($check_domain_id !== null) {
		$updates[] = 'domain_id = ?';
		$params[]  = ($check_domain_id > 0) ? $check_domain_id : null;
	}

	if (empty($updates)) {
		restapi_error(400, 'no_fields', 'No updatable fields provided');
		return;
	}

	$params[] = $id;

	db_execute_prepared(
		'UPDATE plugin_cereus_ipam_vlans SET ' . implode(', ', $updates) . ' WHERE id = ?',
		$params
	);

	$updated = db_fetch_row_prepared(
		'SELECT id, vlan_number, name, description, domain_id, created, modified
		FROM plugin_cereus_ipam_vlans
		WHERE id = ?',
		array($id)
	);

	cacti_log("RESTAPI IPAM: VLAN ID $id updated by user_id " . $context['user_id'], false, 'CEREUS_IPAM');

	cereus_ipam_changelog_record(
		CEREUS_IPAM_ACTION_UPDATE,
		CEREUS_IPAM_OBJ_VLAN,
		$id,
		$existing,
		$input
	);

	restapi_response($updated);
}

/**
 * Delete a VLAN by ID.
 */
function cereus_ipam_restapi_delete_vlan($context) {
	$id = intval($context['id']);

	if ($id <= 0) {
		restapi_error(400, 'invalid_id', 'Invalid VLAN ID');
		return;
	}

	$existing = db_fetch_row_prepared(
		'SELECT * FROM plugin_cereus_ipam_vlans WHERE id = ?',
		array($id)
	);

	if (!cacti_sizeof($existing)) {
		restapi_error(404, 'not_found', "VLAN with ID $id not found");
		return;
	}

	/* Check if any subnets reference this VLAN */
	$subnet_count = db_fetch_cell_prepared(
		'SELECT COUNT(*) FROM plugin_cereus_ipam_subnets WHERE vlan_id = ?',
		array($id)
	);

	if ($subnet_count > 0) {
		restapi_error(409, 'conflict', "Cannot delete VLAN ID $id: $subnet_count subnet(s) still reference this VLAN. Update or delete them first.");
		return;
	}

	db_execute_prepared(
		'DELETE FROM plugin_cereus_ipam_vlans WHERE id = ?',
		array($id)
	);

	cacti_log("RESTAPI IPAM: VLAN ID $id (VLAN " . $existing['vlan_number'] . ") deleted by user_id " . $context['user_id'], false, 'CEREUS_IPAM');

	cereus_ipam_changelog_record(
		CEREUS_IPAM_ACTION_DELETE,
		CEREUS_IPAM_OBJ_VLAN,
		$id,
		$existing,
		null
	);

	restapi_response(null, 204);
}

/* =========================================================================
 * VRFs Endpoint
 * ========================================================================= */

/**
 * GET    /ipam/vrfs         — List all VRFs
 * GET    /ipam/vrfs/{id}    — Get single VRF
 * POST   /ipam/vrfs         — Create VRF
 * PUT    /ipam/vrfs/{id}    — Update VRF
 * DELETE /ipam/vrfs/{id}    — Delete VRF
 */
function cereus_ipam_restapi_vrfs($context) {
	if (!cereus_ipam_license_has_restapi()) {
		restapi_error(403, 'license_required', 'IPAM REST API requires Enterprise license');
		return;
	}

	switch ($context['method']) {
		case 'GET':
			if ($context['id'] !== null) {
				cereus_ipam_restapi_get_vrf($context);
			} else {
				cereus_ipam_restapi_list_vrfs($context);
			}

			break;

		case 'POST':
			if ($context['id'] !== null) {
				restapi_error(400, 'invalid_request', 'POST to a specific VRF ID is not supported');
				return;
			}

			cereus_ipam_restapi_create_vrf($context);

			break;

		case 'PUT':
			if ($context['id'] === null) {
				restapi_error(400, 'missing_id', 'VRF ID is required for updates');
				return;
			}

			cereus_ipam_restapi_update_vrf($context);

			break;

		case 'DELETE':
			if ($context['id'] === null) {
				restapi_error(400, 'missing_id', 'VRF ID is required for deletion');
				return;
			}

			cereus_ipam_restapi_delete_vrf($context);

			break;

		default:
			restapi_error(405, 'method_not_allowed', 'Supported methods: GET, POST, PUT, DELETE');
	}
}

/**
 * List all VRFs.
 */
function cereus_ipam_restapi_list_vrfs($context) {
	$vrfs = db_fetch_assoc_prepared(
		'SELECT id, name, rd, description, created, modified
		FROM plugin_cereus_ipam_vrfs
		ORDER BY name',
		array()
	);

	if (!is_array($vrfs)) {
		$vrfs = array();
	}

	restapi_response($vrfs);
}

/**
 * Get a single VRF by ID.
 */
function cereus_ipam_restapi_get_vrf($context) {
	$id = intval($context['id']);

	if ($id <= 0) {
		restapi_error(400, 'invalid_id', 'Invalid VRF ID');
		return;
	}

	$vrf = db_fetch_row_prepared(
		'SELECT id, name, rd, description, created, modified
		FROM plugin_cereus_ipam_vrfs
		WHERE id = ?',
		array($id)
	);

	if (!cacti_sizeof($vrf)) {
		restapi_error(404, 'not_found', "VRF with ID $id not found");
		return;
	}

	restapi_response($vrf);
}

/**
 * Create a new VRF.
 */
function cereus_ipam_restapi_create_vrf($context) {
	$input = json_decode(file_get_contents('php://input'), true);

	if (!is_array($input)) {
		restapi_error(400, 'invalid_body', 'Request body must be valid JSON');
		return;
	}

	/* Required fields */
	if (empty($input['name'])) {
		restapi_error(400, 'missing_fields', 'Field name is required');
		return;
	}

	$name        = cereus_ipam_sanitize_text($input['name']);
	$rd          = isset($input['rd'])          ? cereus_ipam_sanitize_text($input['rd'])          : null;
	$description = isset($input['description']) ? cereus_ipam_sanitize_text($input['description']) : '';

	/* Validate name not empty after sanitization */
	if ($name === '') {
		restapi_error(400, 'invalid_name', 'VRF name cannot be empty');
		return;
	}

	/* Check duplicate rd if provided */
	if ($rd !== null && $rd !== '') {
		$duplicate = db_fetch_cell_prepared(
			'SELECT COUNT(*) FROM plugin_cereus_ipam_vrfs WHERE rd = ?',
			array($rd)
		);

		if ($duplicate > 0) {
			restapi_error(409, 'duplicate_rd', "A VRF with route distinguisher '$rd' already exists");
			return;
		}
	}

	db_execute_prepared(
		"INSERT INTO plugin_cereus_ipam_vrfs
			(name, rd, description)
		VALUES (?, ?, ?)",
		array($name, $rd, $description)
	);

	$new_id = db_fetch_insert_id();

	if (empty($new_id)) {
		restapi_error(500, 'create_failed', 'Failed to create VRF');
		return;
	}

	$created = db_fetch_row_prepared(
		'SELECT id, name, rd, description, created, modified
		FROM plugin_cereus_ipam_vrfs
		WHERE id = ?',
		array($new_id)
	);

	cacti_log("RESTAPI IPAM: VRF '$name' created (ID: $new_id) by user_id " . $context['user_id'], false, 'CEREUS_IPAM');

	cereus_ipam_changelog_record(
		CEREUS_IPAM_ACTION_CREATE,
		CEREUS_IPAM_OBJ_VRF,
		$new_id,
		null,
		$input
	);

	restapi_response($created, 201);
}

/**
 * Update an existing VRF.
 */
function cereus_ipam_restapi_update_vrf($context) {
	$id = intval($context['id']);

	if ($id <= 0) {
		restapi_error(400, 'invalid_id', 'Invalid VRF ID');
		return;
	}

	$existing = db_fetch_row_prepared(
		'SELECT * FROM plugin_cereus_ipam_vrfs WHERE id = ?',
		array($id)
	);

	if (!cacti_sizeof($existing)) {
		restapi_error(404, 'not_found', "VRF with ID $id not found");
		return;
	}

	$input = json_decode(file_get_contents('php://input'), true);

	if (!is_array($input)) {
		restapi_error(400, 'invalid_body', 'Request body must be valid JSON');
		return;
	}

	/* Build update fields — only update what was provided */
	$updates = array();
	$params  = array();

	if (isset($input['name'])) {
		$name = cereus_ipam_sanitize_text($input['name']);

		if ($name === '') {
			restapi_error(400, 'invalid_name', 'VRF name cannot be empty');
			return;
		}

		$updates[] = 'name = ?';
		$params[]  = $name;
	}

	if (isset($input['rd'])) {
		$rd = cereus_ipam_sanitize_text($input['rd']);

		/* Check duplicate rd if changed */
		if ($rd !== '' && $rd !== $existing['rd']) {
			$duplicate = db_fetch_cell_prepared(
				'SELECT COUNT(*) FROM plugin_cereus_ipam_vrfs WHERE rd = ? AND id != ?',
				array($rd, $id)
			);

			if ($duplicate > 0) {
				restapi_error(409, 'duplicate_rd', "A VRF with route distinguisher '$rd' already exists");
				return;
			}
		}

		$updates[] = 'rd = ?';
		$params[]  = ($rd !== '') ? $rd : null;
	}

	if (isset($input['description'])) {
		$updates[] = 'description = ?';
		$params[]  = cereus_ipam_sanitize_text($input['description']);
	}

	if (empty($updates)) {
		restapi_error(400, 'no_fields', 'No updatable fields provided');
		return;
	}

	$params[] = $id;

	db_execute_prepared(
		'UPDATE plugin_cereus_ipam_vrfs SET ' . implode(', ', $updates) . ' WHERE id = ?',
		$params
	);

	$updated = db_fetch_row_prepared(
		'SELECT id, name, rd, description, created, modified
		FROM plugin_cereus_ipam_vrfs
		WHERE id = ?',
		array($id)
	);

	cacti_log("RESTAPI IPAM: VRF ID $id updated by user_id " . $context['user_id'], false, 'CEREUS_IPAM');

	cereus_ipam_changelog_record(
		CEREUS_IPAM_ACTION_UPDATE,
		CEREUS_IPAM_OBJ_VRF,
		$id,
		$existing,
		$input
	);

	restapi_response($updated);
}

/**
 * Delete a VRF by ID.
 */
function cereus_ipam_restapi_delete_vrf($context) {
	$id = intval($context['id']);

	if ($id <= 0) {
		restapi_error(400, 'invalid_id', 'Invalid VRF ID');
		return;
	}

	$existing = db_fetch_row_prepared(
		'SELECT * FROM plugin_cereus_ipam_vrfs WHERE id = ?',
		array($id)
	);

	if (!cacti_sizeof($existing)) {
		restapi_error(404, 'not_found', "VRF with ID $id not found");
		return;
	}

	/* Check if any subnets reference this VRF */
	$subnet_count = db_fetch_cell_prepared(
		'SELECT COUNT(*) FROM plugin_cereus_ipam_subnets WHERE vrf_id = ?',
		array($id)
	);

	if ($subnet_count > 0) {
		restapi_error(409, 'conflict', "Cannot delete VRF ID $id: $subnet_count subnet(s) still reference this VRF. Update or delete them first.");
		return;
	}

	db_execute_prepared(
		'DELETE FROM plugin_cereus_ipam_vrfs WHERE id = ?',
		array($id)
	);

	cacti_log("RESTAPI IPAM: VRF ID $id ('" . $existing['name'] . "') deleted by user_id " . $context['user_id'], false, 'CEREUS_IPAM');

	cereus_ipam_changelog_record(
		CEREUS_IPAM_ACTION_DELETE,
		CEREUS_IPAM_OBJ_VRF,
		$id,
		$existing,
		null
	);

	restapi_response(null, 204);
}
