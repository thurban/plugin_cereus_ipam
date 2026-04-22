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
 | Cereus IPAM - IP Address Management UI                                  |
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
include_once('./plugins/cereus_ipam/lib/custom_fields.php');
include_once('./plugins/cereus_ipam/lib/rbac.php');

$actions = array(
	1 => __('Delete', 'cereus_ipam'),
	2 => __('Set Active', 'cereus_ipam'),
	3 => __('Set Reserved', 'cereus_ipam'),
	4 => __('Set Offline', 'cereus_ipam'),
	5 => __('Set Available', 'cereus_ipam'),
	6 => __('Set DHCP', 'cereus_ipam'),
);

$action = get_nfilter_request_var('action', '');

switch ($action) {
	case 'save':
		if (get_nfilter_request_var('save_component', '') === 'fill_range') {
			cereus_ipam_address_fill_range_save();
		} else {
			cereus_ipam_address_save();
		}
		break;
	case 'actions':
		cereus_ipam_address_actions();
		break;
	case 'edit':
		top_header();
		cereus_ipam_address_edit();
		bottom_footer();
		break;
	case 'export':
		include_once('./plugins/cereus_ipam/lib/import_export.php');
		$subnet_id = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);
		cereus_ipam_export_csv($subnet_id);
		break;
	case 'fill_range':
		top_header();
		cereus_ipam_address_fill_range_form();
		bottom_footer();
		break;
	case 'fill_range_save':  /* legacy: now routed via save_component */
		cereus_ipam_address_fill_range_save();
		break;
	case 'history':
		top_header();
		cereus_ipam_address_history();
		bottom_footer();
		break;
	case 'visual':
		top_header();
		cereus_ipam_address_visual();
		bottom_footer();
		break;
	case 'visual_data':
		cereus_ipam_address_visual_data();
		break;
	case 'visual_data_chunk':
		cereus_ipam_address_visual_data_chunk();
		break;
	case 'ping':
		cereus_ipam_address_ping_ajax();
		break;
	default:
		top_header();
		cereus_ipam_address_list();
		bottom_footer();
		break;
}

/* ==================== Save ==================== */

function cereus_ipam_address_save() {
	global $cereus_ipam_states;

	if (!isset_request_var('save_component')) {
		return;
	}

	$id        = get_filter_request_var('id');
	$subnet_id = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);

	/* RBAC check */
	if ($subnet_id > 0) {
		$section_id = db_fetch_cell_prepared("SELECT section_id FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
		if ($section_id && !cereus_ipam_check_section_permission($section_id, 'edit')) {
			raise_message('cereus_ipam_perm', __('You do not have permission to edit addresses in this section.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
			header('Location: cereus_ipam_addresses.php?subnet_id=' . $subnet_id);
			exit;
		}
	}

	$ip        = trim(get_nfilter_request_var('ip', ''));
	$hostname  = cereus_ipam_sanitize_text(get_nfilter_request_var('hostname', ''), 255);
	$desc      = cereus_ipam_sanitize_text(get_nfilter_request_var('description', ''), 255);
	$mac       = trim(get_nfilter_request_var('mac_address', ''));
	$owner     = cereus_ipam_sanitize_text(get_nfilter_request_var('owner', ''), 255);
	$dev_type  = cereus_ipam_sanitize_text(get_nfilter_request_var('device_type', ''), 128);
	$dev_loc   = cereus_ipam_sanitize_text(get_nfilter_request_var('device_location', ''), 255);
	$state     = get_nfilter_request_var('state', 'available');
	$note      = cereus_ipam_sanitize_text(get_nfilter_request_var('note', ''), 65535);
	$port      = cereus_ipam_sanitize_text(get_nfilter_request_var('port', ''), 64);
	$nat_inside  = trim(get_nfilter_request_var('nat_inside', ''));
	$nat_outside = trim(get_nfilter_request_var('nat_outside', ''));

	/* Helper to preserve form data on validation failure */
	$form_data = array(
		'ip' => $ip, 'hostname' => $hostname, 'description' => $desc,
		'mac_address' => $mac, 'owner' => $owner, 'device_type' => $dev_type,
		'device_location' => $dev_loc, 'state' => $state, 'note' => $note,
		'port' => $port, 'nat_inside' => $nat_inside, 'nat_outside' => $nat_outside,
	);

	/* Validate IP */
	if (!cereus_ipam_validate_ip($ip)) {
		$_SESSION['cipam_form_addr'] = $form_data;
		raise_message('cereus_ipam_ip', __('Invalid IP address.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_addresses.php?action=edit&id=' . $id . '&subnet_id=' . $subnet_id);
		exit;
	}

	/* Check IP in subnet */
	$subnet = db_fetch_row_prepared("SELECT subnet, mask FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
	if (cacti_sizeof($subnet) && !cereus_ipam_ip_in_subnet($ip, $subnet['subnet'], $subnet['mask'])) {
		$_SESSION['cipam_form_addr'] = $form_data;
		raise_message('cereus_ipam_range', __('IP address is not within the selected subnet.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_addresses.php?action=edit&id=' . $id . '&subnet_id=' . $subnet_id);
		exit;
	}

	/* Validate state */
	if (!cereus_ipam_validate_state($state)) {
		$state = 'available';
	}

	/* Normalize MAC */
	if (!empty($mac)) {
		$mac_norm = cereus_ipam_normalize_mac($mac);
		if ($mac_norm === false) {
			$_SESSION['cipam_form_addr'] = $form_data;
			raise_message('cereus_ipam_mac', __('Invalid MAC address format. Use XX:XX:XX:XX:XX:XX.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
			header('Location: cereus_ipam_addresses.php?action=edit&id=' . $id . '&subnet_id=' . $subnet_id);
			exit;
		}
		$mac = $mac_norm;
	}

	/* NAT fields (Professional+) */
	if (!cereus_ipam_license_has_nat()) {
		$nat_inside = '';
		$nat_outside = '';
	} else {
		if (!empty($nat_inside) && !cereus_ipam_validate_ip($nat_inside)) {
			$nat_inside = '';
		}
		if (!empty($nat_outside) && !cereus_ipam_validate_ip($nat_outside)) {
			$nat_outside = '';
		}
	}

	/* Location (Enterprise) */
	$location_id = 0;
	if (cereus_ipam_license_has_locations()) {
		$location_id = get_filter_request_var('location_id', FILTER_VALIDATE_INT);
		if ($location_id === false || $location_id < 0) {
			$location_id = 0;
		}
	}

	$user_id = $_SESSION['sess_user_id'] ?? 0;

	if ($id > 0) {
		$old = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_addresses WHERE id = ?", array($id));
		db_execute_prepared("UPDATE plugin_cereus_ipam_addresses SET
			subnet_id = ?, ip = ?, hostname = ?, description = ?,
			mac_address = ?, owner = ?, device_type = ?, device_location = ?,
			state = ?, note = ?, port = ?, nat_inside = ?, nat_outside = ?, location_id = ?
			WHERE id = ?",
			array($subnet_id, $ip, $hostname, $desc, $mac, $owner, $dev_type, $dev_loc, $state, $note, $port, $nat_inside, $nat_outside, ($location_id > 0 ? $location_id : null), $id));
		cereus_ipam_changelog_record('update', 'address', $id, $old, array('ip' => $ip, 'state' => $state));
		$new_id = $id;
	} else {
		/* Check for duplicate */
		$existing = db_fetch_cell_prepared("SELECT id FROM plugin_cereus_ipam_addresses WHERE subnet_id = ? AND ip = ?",
			array($subnet_id, $ip));
		if ($existing) {
			$_SESSION['cipam_form_addr'] = $form_data;
			raise_message('cereus_ipam_dup', __('IP address already exists in this subnet.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
			header('Location: cereus_ipam_addresses.php?action=edit&id=0&subnet_id=' . $subnet_id);
			exit;
		}

		db_execute_prepared("INSERT INTO plugin_cereus_ipam_addresses
			(subnet_id, ip, hostname, description, mac_address, owner, device_type,
			 device_location, state, note, port, nat_inside, nat_outside, location_id, created_by)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			array($subnet_id, $ip, $hostname, $desc, $mac, $owner, $dev_type, $dev_loc, $state, $note, $port, $nat_inside, $nat_outside, ($location_id > 0 ? $location_id : null), $user_id));
		$new_id = db_fetch_insert_id();
		cereus_ipam_changelog_record('create', 'address', $new_id, null, array('ip' => $ip, 'subnet_id' => $subnet_id));
	}

	/* Save custom fields */
	if (cereus_ipam_license_has_custom_fields()) {
		$cf_json = cereus_ipam_save_custom_fields('address');
		$save_id = ($id > 0) ? $id : db_fetch_insert_id();
		if ($save_id > 0) {
			db_execute_prepared("UPDATE plugin_cereus_ipam_addresses SET custom_fields = ? WHERE id = ?",
				array($cf_json, $save_id));
		}
	}

	/* Save tag assignments */
	$tag_save_id = ($id > 0) ? $id : $new_id;
	if ($tag_save_id > 0) {
		$tag_ids = array();
		if (isset($_POST['tag_ids']) && is_array($_POST['tag_ids'])) {
			$tag_ids = $_POST['tag_ids'];
		}
		cereus_ipam_save_object_tags('address', $tag_save_id, $tag_ids);
	}

	raise_message('cereus_ipam_saved', __('Address saved.', 'cereus_ipam'), MESSAGE_LEVEL_INFO);
	header('Location: cereus_ipam_addresses.php?subnet_id=' . $subnet_id);
	exit;
}

/* ==================== Bulk Actions ==================== */

function cereus_ipam_address_actions() {
	global $actions;

	$subnet_id = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);

	if (isset_request_var('selected_items')) {
		$selected_items = sanitize_unserialize_selected_items(get_nfilter_request_var('selected_items'));

		if ($selected_items !== false) {
			$drp_action = get_nfilter_request_var('drp_action');

			foreach ($selected_items as $id) {
				if (!is_numeric($id) || $id <= 0) continue;

				switch ($drp_action) {
					case '1': /* delete */
						$old = db_fetch_row_prepared("SELECT ip FROM plugin_cereus_ipam_addresses WHERE id = ?", array($id));
						db_execute_prepared("DELETE FROM plugin_cereus_ipam_tag_assignments WHERE object_type = 'address' AND object_id = ?", array($id));
						db_execute_prepared("DELETE FROM plugin_cereus_ipam_addresses WHERE id = ?", array($id));
						if (cacti_sizeof($old)) {
							cereus_ipam_changelog_record('delete', 'address', $id, $old, null);
						}
						break;
					case '2': /* active */
						db_execute_prepared("UPDATE plugin_cereus_ipam_addresses SET state = 'active' WHERE id = ?", array($id));
						break;
					case '3': /* reserved */
						db_execute_prepared("UPDATE plugin_cereus_ipam_addresses SET state = 'reserved' WHERE id = ?", array($id));
						break;
					case '4': /* offline */
						db_execute_prepared("UPDATE plugin_cereus_ipam_addresses SET state = 'offline' WHERE id = ?", array($id));
						break;
					case '5': /* available */
						db_execute_prepared("UPDATE plugin_cereus_ipam_addresses SET state = 'available' WHERE id = ?", array($id));
						break;
					case '6': /* dhcp */
						db_execute_prepared("UPDATE plugin_cereus_ipam_addresses SET state = 'dhcp' WHERE id = ?", array($id));
						break;
				}
			}
		}

		header('Location: cereus_ipam_addresses.php?subnet_id=' . $subnet_id);
		exit;
	}

	/* Confirmation page */
	$item_array = array();
	foreach ($_POST as $var => $val) {
		if (preg_match('/^chk_([0-9]+)$/', $var, $matches)) {
			$item_array[] = $matches[1];
		}
	}

	top_header();
	form_start('cereus_ipam_addresses.php');
	html_start_box($actions[get_nfilter_request_var('drp_action')], '60%', '', '3', 'center', '');

	if (cacti_sizeof($item_array)) {
		foreach ($item_array as $id) {
			$row = db_fetch_row_prepared('SELECT ip, hostname FROM plugin_cereus_ipam_addresses WHERE id = ?', array($id));
			if (cacti_sizeof($row)) {
				print '<tr><td class="odd"><span class="deleteMarker">' . html_escape($row['ip']) . ' (' . html_escape($row['hostname'] ?? '') . ')</span></td></tr>';
			}
		}
	}

	print '<tr><td class="saveRow"><p>' . __('Are you sure you want to %s the selected address(es)?',
		strtolower($actions[get_nfilter_request_var('drp_action')]), 'cereus_ipam') . '</p></td></tr>';

	$save_html = "<input type='button' class='ui-button ui-corner-all ui-widget' value='" . __esc('Cancel', 'cereus_ipam') . "' onClick='cactiReturnTo(\"cereus_ipam_addresses.php?subnet_id=" . $subnet_id . "\")'>&nbsp;";
	$save_html .= "<input type='submit' class='ui-button ui-corner-all ui-widget' value='" . __esc('Continue', 'cereus_ipam') . "'>";
	print "<tr><td class='saveRow'>$save_html</td></tr>";

	html_end_box();
	form_hidden_box('action', 'actions', '');
	form_hidden_box('subnet_id', $subnet_id, '0');
	form_hidden_box('selected_items', serialize($item_array), '');
	form_hidden_box('drp_action', get_nfilter_request_var('drp_action'), '');
	form_end();
	bottom_footer();
}

/* ==================== Edit Form ==================== */

function cereus_ipam_address_edit() {
	global $config, $cereus_ipam_states;

	$id        = get_filter_request_var('id');
	$subnet_id = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);

	/* RBAC check */
	if ($subnet_id > 0) {
		$section_id = db_fetch_cell_prepared("SELECT section_id FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
		if ($section_id && !cereus_ipam_check_section_permission($section_id, 'edit')) {
			raise_message('cereus_ipam_perm', __('You do not have permission to edit addresses in this section.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
			header('Location: cereus_ipam_addresses.php?subnet_id=' . $subnet_id);
			exit;
		}
	}

	if ($id > 0) {
		$addr = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_addresses WHERE id = ?", array($id));
		if (!cacti_sizeof($addr)) {
			raise_message('cereus_ipam_nf', __('Address not found.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
			header('Location: cereus_ipam_addresses.php?subnet_id=' . $subnet_id);
			exit;
		}
		$subnet_id = $addr['subnet_id'];
		$header = __('Edit Address: %s', html_escape($addr['ip']), 'cereus_ipam');
	} else {
		$addr = array();
		/* Pre-fill with specific IP from visual map click, or next available */
		$prefill_ip = get_nfilter_request_var('prefill_ip', '');
		if (!empty($prefill_ip) && filter_var($prefill_ip, FILTER_VALIDATE_IP)) {
			$addr['ip'] = $prefill_ip;
		} else {
			$next_ip = cereus_ipam_next_available($subnet_id);
			if ($next_ip) {
				$addr['ip'] = $next_ip;
			}
		}
		$header = __('New Address', 'cereus_ipam');
	}

	/* Restore form data from session after validation error */
	if (isset($_SESSION['cipam_form_addr']) && is_array($_SESSION['cipam_form_addr'])) {
		$addr = array_merge($addr, $_SESSION['cipam_form_addr']);
		unset($_SESSION['cipam_form_addr']);
	}

	/* Get subnet info for context */
	$subnet = db_fetch_row_prepared("SELECT subnet, mask FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
	$subnet_label = cacti_sizeof($subnet) ? ($subnet['subnet'] . '/' . $subnet['mask']) : __('Unknown', 'cereus_ipam');

	$fields = array(
		'general_header' => array(
			'friendly_name' => __('Address in Subnet %s', $subnet_label, 'cereus_ipam'),
			'method'        => 'spacer',
		),
		'ip' => array(
			'friendly_name' => __('IP Address', 'cereus_ipam'),
			'description'   => __('The IP address.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $addr['ip'] ?? '',
			'max_length'    => 45,
			'size'          => 40,
		),
		'hostname' => array(
			'friendly_name' => __('Hostname', 'cereus_ipam'),
			'description'   => __('DNS hostname or FQDN.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $addr['hostname'] ?? '',
			'max_length'    => 255,
			'size'          => 50,
		),
		'description' => array(
			'friendly_name' => __('Description', 'cereus_ipam'),
			'description'   => __('Short description.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $addr['description'] ?? '',
			'max_length'    => 255,
			'size'          => 60,
		),
		'state' => array(
			'friendly_name' => __('State', 'cereus_ipam'),
			'description'   => __('Current state of this IP.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'value'         => $addr['state'] ?? 'available',
			'array'         => $cereus_ipam_states,
		),
		'mac_address' => array(
			'friendly_name' => __('MAC Address', 'cereus_ipam'),
			'description'   => __('Format: XX:XX:XX:XX:XX:XX', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $addr['mac_address'] ?? '',
			'max_length'    => 17,
			'size'          => 20,
		),
		'owner' => array(
			'friendly_name' => __('Owner', 'cereus_ipam'),
			'description'   => __('Person or team responsible.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $addr['owner'] ?? '',
			'max_length'    => 255,
			'size'          => 40,
		),
		'device_type' => array(
			'friendly_name' => __('Device Type', 'cereus_ipam'),
			'description'   => __('Type of device (server, switch, printer, etc.).', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $addr['device_type'] ?? '',
			'max_length'    => 128,
			'size'          => 30,
		),
		'device_location' => array(
			'friendly_name' => __('Location', 'cereus_ipam'),
			'description'   => __('Physical location.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $addr['device_location'] ?? '',
			'max_length'    => 255,
			'size'          => 40,
		),
		'port' => array(
			'friendly_name' => __('Switch Port', 'cereus_ipam'),
			'description'   => __('Switch port (e.g., Gi0/1).', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $addr['port'] ?? '',
			'max_length'    => 64,
			'size'          => 20,
		),
		'note' => array(
			'friendly_name' => __('Notes', 'cereus_ipam'),
			'description'   => __('Additional notes.', 'cereus_ipam'),
			'method'        => 'textarea',
			'value'         => $addr['note'] ?? '',
			'textarea_rows' => 3,
			'textarea_cols' => 60,
			'max_length'    => 65535,
		),
	);

	/* NAT fields (Professional+) */
	if (cereus_ipam_license_has_nat()) {
		$fields['nat_header'] = array(
			'friendly_name' => __('NAT Mapping', 'cereus_ipam'),
			'method'        => 'spacer',
		);
		$fields['nat_inside'] = array(
			'friendly_name' => __('NAT Inside', 'cereus_ipam'),
			'description'   => __('Inside (private) address.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $addr['nat_inside'] ?? '',
			'max_length'    => 45,
			'size'          => 40,
		);
		$fields['nat_outside'] = array(
			'friendly_name' => __('NAT Outside', 'cereus_ipam'),
			'description'   => __('Outside (public) address.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $addr['nat_outside'] ?? '',
			'max_length'    => 45,
			'size'          => 40,
		);
	}

	/* Location (Enterprise) */
	if (cereus_ipam_license_has_locations()) {
		$fields['location_header'] = array(
			'friendly_name' => __('Rack/Location', 'cereus_ipam'),
			'method'        => 'spacer',
		);
		$fields['location_id'] = array(
			'friendly_name' => __('Location', 'cereus_ipam'),
			'description'   => __('Assign this address to a rack/location.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'value'         => $addr['location_id'] ?? '0',
			'array'         => cereus_ipam_get_locations_dropdown(),
		);
	}

	/* Location assignment (Enterprise) */
	if (cereus_ipam_license_has_locations()) {
		$fields['location_header'] = array(
			'friendly_name' => __('Location Assignment', 'cereus_ipam'),
			'method'        => 'spacer',
		);
		$fields['location_id'] = array(
			'friendly_name' => __('Location', 'cereus_ipam'),
			'description'   => __('Assign this address to a physical location (site, building, floor, room, rack).', 'cereus_ipam'),
			'method'        => 'drop_array',
			'value'         => $addr['location_id'] ?? 0,
			'array'         => cereus_ipam_get_locations_dropdown(),
		);
	}

	/* Custom fields (Professional+) */
	if (cereus_ipam_license_has_custom_fields()) {
		$cf_values = json_decode($addr['custom_fields'] ?? '{}', true);
		if (!is_array($cf_values)) $cf_values = array();
		$cf_fields = cereus_ipam_render_custom_fields('address', $cf_values);
		if (cacti_sizeof($cf_fields)) {
			$fields['cf_spacer'] = array(
				'friendly_name' => __('Custom Fields', 'cereus_ipam'),
				'method' => 'spacer',
			);
			$fields = array_merge($fields, $cf_fields);
		}
	}

	form_start('cereus_ipam_addresses.php');
	html_start_box($header, '100%', '', '3', 'center', '');
	draw_edit_form(array(
		'config' => array('no_form_tag' => true),
		'fields' => $fields,
	));
	html_end_box();

	/* Cacti device link info */
	if ($id > 0 && !empty($addr['cacti_host_id'])) {
		$host = db_fetch_row_prepared("SELECT id, description, hostname, status FROM host WHERE id = ?", array($addr['cacti_host_id']));
		if (cacti_sizeof($host)) {
			$status_text = ($host['status'] == 3) ? "<span class='deviceUp'>" . __('Up', 'cereus_ipam') . "</span>"
				: "<span class='deviceDown'>" . __('Down', 'cereus_ipam') . "</span>";

			html_start_box(__('Linked Cacti Device', 'cereus_ipam'), '100%', '', '3', 'center', '');
			print '<tr class="even"><td style="padding:8px 15px;">';
			print '<b>' . __('Device:', 'cereus_ipam') . '</b> ';
			print '<a href="' . html_escape($config['url_path']) . 'host.php?action=edit&id=' . $host['id'] . '">' . html_escape($host['description']) . '</a>';
			print ' (' . html_escape($host['hostname']) . ') - ' . $status_text;
			print '</td></tr>';
			html_end_box();
		}
	}

	/* Tags selector */
	$all_tags = cereus_ipam_get_all_tags();
	if (cacti_sizeof($all_tags)) {
		$assigned_tag_ids = array();
		if ($id > 0) {
			$assigned = cereus_ipam_get_object_tags('address', $id);
			foreach ($assigned as $at) {
				$assigned_tag_ids[] = $at['id'];
			}
		}

		html_start_box(__('Tags', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr class="even"><td style="padding:8px 15px;">';
		foreach ($all_tags as $tag) {
			$checked = in_array($tag['id'], $assigned_tag_ids) ? ' checked' : '';
			$bg = html_escape($tag['color']);
			$r = hexdec(substr($bg, 1, 2));
			$g = hexdec(substr($bg, 3, 2));
			$b = hexdec(substr($bg, 5, 2));
			$tc = (($r * 299 + $g * 587 + $b * 114) / 1000) > 128 ? '#000' : '#fff';
			print '<label style="display:inline-block;margin:2px 8px 2px 0;cursor:pointer;">'
				. '<input type="checkbox" name="tag_ids[]" value="' . $tag['id'] . '"' . $checked . '> '
				. '<span style="display:inline-block;padding:1px 6px;border-radius:3px;font-size:11px;'
				. 'background-color:' . $bg . ';color:' . $tc . ';">' . html_escape($tag['name']) . '</span>'
				. '</label>';
		}
		print '</td></tr>';
		html_end_box();
	}

	form_hidden_box('id', $id, '0');
	form_hidden_box('subnet_id', $subnet_id, '0');
	form_hidden_box('save_component', '1', '');
	form_save_button('cereus_ipam_addresses.php?subnet_id=' . $subnet_id, 'return');
}

/* ==================== List View ==================== */

function cereus_ipam_address_list() {
	global $config, $actions, $cereus_ipam_states;

	$subnet_id = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);

	if (!$subnet_id) {
		raise_message('cereus_ipam_nosub', __('No subnet selected.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam.php');
		exit;
	}

	$subnet = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
	if (!cacti_sizeof($subnet)) {
		raise_message('cereus_ipam_nf', __('Subnet not found.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam.php');
		exit;
	}

	/* Filter handling */
	if (isset_request_var('clear')) {
		kill_session_var('sess_cipam_addr_filter');
		kill_session_var('sess_cipam_addr_state');
		kill_session_var('sess_cipam_addr_owner');
		kill_session_var('sess_cipam_addr_devtype');
		kill_session_var('sess_cipam_addr_regex');
		kill_session_var('sess_cipam_addr_location');
		kill_session_var('sess_cipam_addr_tag');
		kill_session_var('sess_cipam_addr_rows');
		kill_session_var('sess_cipam_addr_page');
		unset_request_var('filter');
		unset_request_var('state');
		unset_request_var('owner');
		unset_request_var('device_type');
		unset_request_var('use_regex');
		unset_request_var('location_id');
		unset_request_var('tag_id');
		unset_request_var('rows');
		unset_request_var('page');
	}

	load_current_session_value('filter',      'sess_cipam_addr_filter',   '');
	load_current_session_value('state',       'sess_cipam_addr_state',    '-1');
	load_current_session_value('owner',       'sess_cipam_addr_owner',    '-1');
	load_current_session_value('device_type', 'sess_cipam_addr_devtype',  '-1');
	load_current_session_value('use_regex',   'sess_cipam_addr_regex',    '');
	load_current_session_value('location_id', 'sess_cipam_addr_location', '-1');
	load_current_session_value('tag_id',     'sess_cipam_addr_tag',      '-1');
	load_current_session_value('rows',        'sess_cipam_addr_rows',     '-1');
	load_current_session_value('page',        'sess_cipam_addr_page',     '1');

	$filter        = get_request_var('filter');
	$state         = get_request_var('state');
	$owner_filt    = get_request_var('owner');
	$devtype_filt  = get_request_var('device_type');
	$use_regex     = get_request_var('use_regex');
	$location_filt = get_request_var('location_id');
	$tag_filt      = get_request_var('tag_id');
	$rows          = get_request_var('rows');
	$page          = get_request_var('page');

	if ($rows == -1) {
		$rows = read_config_option('num_rows_table');
	}
	$rows = max(1, (int) $rows);
	$page = max(1, (int) $page);

	$util = cereus_ipam_subnet_utilization($subnet_id);

	/* Filter bar */
	html_start_box(
		__('Addresses in %s/%s', html_escape($subnet['subnet']), $subnet['mask'], 'cereus_ipam')
		. ' (' . $util['used'] . '/' . $util['total'] . ' ' . __('used', 'cereus_ipam') . ')',
		'100%', '', '3', 'center',
		'cereus_ipam_addresses.php?action=edit&id=0&subnet_id=' . $subnet_id
	);
	?>
	<tr class='even'>
		<td>
			<form id='form_cipam_addr' action='cereus_ipam_addresses.php'>
				<table class='filterTable'>
					<tr>
						<td><?php print __('Search', 'cereus_ipam'); ?></td>
						<td><input type='text' class='ui-state-default ui-corner-all' id='filter' value='<?php print html_escape($filter); ?>'></td>
						<?php if (cereus_ipam_license_has_advanced_search()) { ?>
						<td><label><input type='checkbox' id='use_regex' <?php print ($use_regex == 'on' ? 'checked' : ''); ?>> <?php print __('Regex', 'cereus_ipam'); ?></label></td>
						<?php } ?>
						<td><?php print __('State', 'cereus_ipam'); ?></td>
						<td>
							<select id='state'>
								<option value='-1' <?php print ($state == '-1' ? 'selected' : ''); ?>><?php print __('All', 'cereus_ipam'); ?></option>
								<?php
								foreach ($cereus_ipam_states as $k => $v) {
									print "<option value='" . html_escape($k) . "'" . ($state == $k ? ' selected' : '') . ">" . html_escape($v) . "</option>\n";
								}
								?>
							</select>
						</td>
						<td>
							<span>
								<input type='button' class='ui-button' id='refresh' value='<?php print __esc('Go', 'cereus_ipam'); ?>'>
								<input type='button' class='ui-button' id='clear' value='<?php print __esc('Clear', 'cereus_ipam'); ?>'>
								<input type='button' class='ui-button' id='export_csv' value='<?php print __esc('CSV Export', 'cereus_ipam'); ?>'>
								<input type='button' class='ui-button' id='fill_range' value='<?php print __esc('Fill Range', 'cereus_ipam'); ?>'>
								<input type='button' class='ui-button' id='visual_map' value='<?php print __esc('Visual Map', 'cereus_ipam'); ?>'>
							</span>
						</td>
					</tr>
					<tr>
						<td><?php print __('Owner', 'cereus_ipam'); ?></td>
						<td>
							<select id='owner' class='ui-state-default ui-corner-all'>
								<option value='-1'<?php print ($owner_filt == '-1' ? ' selected' : ''); ?>><?php print __('All', 'cereus_ipam'); ?></option>
								<?php
								$owners = db_fetch_assoc_prepared("SELECT DISTINCT owner FROM plugin_cereus_ipam_addresses WHERE subnet_id = ? AND owner IS NOT NULL AND owner != '' ORDER BY owner", array($subnet_id));
								if (cacti_sizeof($owners)) foreach ($owners as $o) {
									print "<option value='" . html_escape($o['owner']) . "'" . ($owner_filt == $o['owner'] ? ' selected' : '') . ">" . html_escape($o['owner']) . "</option>\n";
								}
								?>
							</select>
						</td>
						<td><?php print __('Device Type', 'cereus_ipam'); ?></td>
						<td>
							<select id='device_type' class='ui-state-default ui-corner-all'>
								<option value='-1'<?php print ($devtype_filt == '-1' ? ' selected' : ''); ?>><?php print __('All', 'cereus_ipam'); ?></option>
								<?php
								$devtypes = db_fetch_assoc_prepared("SELECT DISTINCT device_type FROM plugin_cereus_ipam_addresses WHERE subnet_id = ? AND device_type IS NOT NULL AND device_type != '' ORDER BY device_type", array($subnet_id));
								if (cacti_sizeof($devtypes)) foreach ($devtypes as $dt) {
									print "<option value='" . html_escape($dt['device_type']) . "'" . ($devtype_filt == $dt['device_type'] ? ' selected' : '') . ">" . html_escape($dt['device_type']) . "</option>\n";
								}
								?>
							</select>
						</td>
						<?php if (cereus_ipam_license_has_locations()) { ?>
						<td><?php print __('Location', 'cereus_ipam'); ?></td>
						<td>
							<select id='location_id' class='ui-state-default ui-corner-all'>
								<option value='-1'<?php print ($location_filt == '-1' ? ' selected' : ''); ?>><?php print __('All', 'cereus_ipam'); ?></option>
								<option value='0'<?php print ($location_filt == '0' ? ' selected' : ''); ?>><?php print __('No Location', 'cereus_ipam'); ?></option>
								<?php
								$loc_dd = cereus_ipam_get_locations_dropdown();
								unset($loc_dd[0]);
								foreach ($loc_dd as $loc_id => $loc_name) {
									print "<option value='" . (int)$loc_id . "'" . ($location_filt == $loc_id ? ' selected' : '') . ">" . html_escape($loc_name) . "</option>\n";
								}
								?>
							</select>
						</td>
						<?php } ?>
						<td><?php print __('Tag', 'cereus_ipam'); ?></td>
						<td>
							<select id='tag_id' class='ui-state-default ui-corner-all'>
								<option value='-1'<?php print ($tag_filt == '-1' ? ' selected' : ''); ?>><?php print __('All', 'cereus_ipam'); ?></option>
								<option value='0'<?php print ($tag_filt == '0' ? ' selected' : ''); ?>><?php print __('No Tags', 'cereus_ipam'); ?></option>
								<?php
								$tag_dd = cereus_ipam_get_tags_dropdown();
								foreach ($tag_dd as $t_id => $t_name) {
									print "<option value='" . (int)$t_id . "'" . ($tag_filt == $t_id ? ' selected' : '') . ">" . html_escape($t_name) . "</option>\n";
								}
								?>
							</select>
						</td>
					</tr>
				</table>
				<input type='hidden' id='subnet_id' value='<?php print $subnet_id; ?>'>
			</form>
			<script type='text/javascript'>
			function applyFilter() {
				var url = 'cereus_ipam_addresses.php?header=false&subnet_id=<?php print $subnet_id; ?>'
					+ '&filter=' + encodeURIComponent($('#filter').val())
					+ '&state=' + $('#state').val()
					+ '&owner=' + encodeURIComponent($('#owner').val())
					+ '&device_type=' + encodeURIComponent($('#device_type').val())
					+ '&use_regex=' + ($('#use_regex').length && $('#use_regex').is(':checked') ? 'on' : '')
					+ '&location_id=' + ($('#location_id').length ? $('#location_id').val() : '-1')
					+ '&tag_id=' + $('#tag_id').val();
				loadPageNoHeader(url);
			}
			$(function() {
				$('#refresh').click(function() { applyFilter(); });
				$('#clear').click(function() { loadPageNoHeader('cereus_ipam_addresses.php?header=false&subnet_id=<?php print $subnet_id; ?>&clear=1'); });
				$('#state').change(function() { applyFilter(); });
				$('#owner').change(function() { applyFilter(); });
				$('#device_type').change(function() { applyFilter(); });
				$('#location_id').change(function() { applyFilter(); });
				$('#tag_id').change(function() { applyFilter(); });
				$('#filter').keypress(function(e) { if (e.which == 13) { applyFilter(); e.preventDefault(); } });
				$('#export_csv').click(function() {
					document.location = 'cereus_ipam_addresses.php?action=export&subnet_id=<?php print $subnet_id; ?>';
				});
				$('#fill_range').click(function() {
					document.location = 'cereus_ipam_addresses.php?action=fill_range&subnet_id=<?php print $subnet_id; ?>';
				});
				$('#visual_map').click(function() {
					document.location = 'cereus_ipam_addresses.php?action=visual&subnet_id=<?php print $subnet_id; ?>';
				});
			});
			</script>
		</td>
	</tr>
	<?php
	html_end_box();

	/* Next available IP indicator */
	$next_ip = cereus_ipam_next_available($subnet_id);
	if ($next_ip !== false) {
		print '<div style="padding:4px 8px;margin-bottom:4px;font-size:12px;color:#555;">';
		print '<i class="fa fa-arrow-right" style="color:#27ae60;"></i> ';
		print __('Next available:', 'cereus_ipam') . ' <strong>' . html_escape($next_ip) . '</strong>';
		print ' &mdash; <a href="cereus_ipam_addresses.php?action=edit&id=0&subnet_id=' . $subnet_id . '&prefill_ip=' . urlencode($next_ip) . '">' . __('Create', 'cereus_ipam') . '</a>';
		print '</div>';
	}

	/* Build SQL */
	$sql_where  = 'WHERE a.subnet_id = ?';
	$sql_params = array($subnet_id);

	if (!empty($filter)) {
		if ($use_regex == 'on' && cereus_ipam_license_has_advanced_search()) {
			$sql_where .= ' AND (a.ip REGEXP ? OR a.hostname REGEXP ? OR a.description REGEXP ? OR a.mac_address REGEXP ? OR a.owner REGEXP ?)';
			$sql_params[] = $filter;
			$sql_params[] = $filter;
			$sql_params[] = $filter;
			$sql_params[] = $filter;
			$sql_params[] = $filter;
		} else {
			$safe = str_replace(array('%', '_'), array('\\%', '\\_'), $filter);
			$sql_where .= ' AND (a.ip LIKE ? OR a.hostname LIKE ? OR a.description LIKE ? OR a.mac_address LIKE ? OR a.owner LIKE ?)';
			$sql_params[] = '%' . $safe . '%';
			$sql_params[] = '%' . $safe . '%';
			$sql_params[] = '%' . $safe . '%';
			$sql_params[] = '%' . $safe . '%';
			$sql_params[] = '%' . $safe . '%';
		}
	}

	if ($state != '-1') {
		$sql_where .= ' AND a.state = ?';
		$sql_params[] = $state;
	}

	if ($owner_filt != '-1') {
		$sql_where .= ' AND a.owner = ?';
		$sql_params[] = $owner_filt;
	}

	if ($devtype_filt != '-1') {
		$sql_where .= ' AND a.device_type = ?';
		$sql_params[] = $devtype_filt;
	}

	if (cereus_ipam_license_has_locations() && $location_filt != '-1') {
		if ($location_filt == '0') {
			$sql_where .= ' AND (a.location_id IS NULL OR a.location_id = 0)';
		} else {
			$sql_where .= ' AND a.location_id = ?';
			$sql_params[] = $location_filt;
		}
	}

	if ($tag_filt != '-1') {
		if ($tag_filt == '0') {
			$sql_where .= ' AND a.id NOT IN (SELECT object_id FROM plugin_cereus_ipam_tag_assignments WHERE object_type = \'address\')';
		} else {
			$sql_where .= ' AND a.id IN (SELECT object_id FROM plugin_cereus_ipam_tag_assignments WHERE object_type = \'address\' AND tag_id = ?)';
			$sql_params[] = $tag_filt;
		}
	}

	$total_rows = db_fetch_cell_prepared(
		"SELECT COUNT(*) FROM plugin_cereus_ipam_addresses a $sql_where",
		$sql_params
	);

	$addresses = db_fetch_assoc_prepared(
		"SELECT a.*, h.description AS device_desc, h.status AS device_status
		FROM plugin_cereus_ipam_addresses a
		LEFT JOIN host h ON h.id = a.cacti_host_id
		$sql_where
		ORDER BY INET_ATON(a.ip)
		LIMIT " . (($page - 1) * $rows) . ", $rows",
		$sql_params
	);

	$nav = html_nav_bar('cereus_ipam_addresses.php?subnet_id=' . $subnet_id, MAX_DISPLAY_PAGES, $page, $rows, $total_rows, 9, __('Addresses', 'cereus_ipam'));
	print $nav;

	/* Bulk-fetch tags for all displayed addresses */
	$address_tags = array();
	if (cacti_sizeof($addresses)) {
		$addr_ids = array_column($addresses, 'id');
		$address_tags = cereus_ipam_get_bulk_tags('address', $addr_ids);
	}

	form_start('cereus_ipam_addresses.php', 'chk');
	html_start_box('', '100%', '', '3', 'center', '');

	$display_text = array(
		'ip'          => array('display' => __('IP Address', 'cereus_ipam'),  'sort' => 'ASC'),
		'hostname'    => array('display' => __('Hostname', 'cereus_ipam'),    'sort' => 'ASC'),
		'description' => array('display' => __('Description', 'cereus_ipam'), 'sort' => 'ASC'),
		'state'       => array('display' => __('State', 'cereus_ipam'),       'sort' => 'ASC'),
		'mac_address' => array('display' => __('MAC', 'cereus_ipam'),         'sort' => 'ASC'),
		'owner'       => array('display' => __('Owner', 'cereus_ipam'),       'sort' => 'ASC'),
		'nosort1'     => array('display' => __('Device', 'cereus_ipam')),
		'last_seen'   => array('display' => __('Last Seen', 'cereus_ipam'),   'sort' => 'DESC'),
	);

	if (cereus_ipam_license_has_nat()) {
		$display_text[] = array('display' => __('NAT Inside', 'cereus_ipam'), 'align' => 'left');
		$display_text[] = array('display' => __('NAT Outside', 'cereus_ipam'), 'align' => 'left');
	}

	if (cereus_ipam_license_has_locations()) {
		$display_text['nosort_location'] = array('display' => __('Location', 'cereus_ipam'));
	}

	html_header_sort_checkbox($display_text, get_request_var('sort_column', 'ip'), get_request_var('sort_direction', 'ASC'));

	if (cacti_sizeof($addresses)) {
		foreach ($addresses as $row) {
			form_alternate_row('line' . $row['id'], true);

			$ip_escaped = html_escape($row['ip']);
			form_selectable_cell(
				'<a class="linkEditMain" href="cereus_ipam_addresses.php?action=edit&id=' . $row['id'] . '&subnet_id=' . $subnet_id . '">'
				. $ip_escaped . '</a>'
				. ' <a href="cereus_ipam_addresses.php?action=history&id=' . $row['id'] . '&subnet_id=' . $subnet_id . '" title="' . __esc('View History', 'cereus_ipam') . '" style="font-size:10px;color:#999;">[H]</a>'
				. ' <a href="#" class="cipam-ping-btn" data-ip="' . $ip_escaped . '" title="' . __esc('Ping', 'cereus_ipam') . '" style="font-size:11px;color:#999;"><i class="fa fa-heartbeat"></i></a>'
				. '<span class="cipam-ping-result" id="ping_' . $row['id'] . '" style="font-size:10px;margin-left:4px;"></span>',
				$row['id']
			);
			form_selectable_cell(html_escape($row['hostname'] ?? ''), $row['id']);
			$addr_desc_html = html_escape($row['description'] ?? '');
			if (isset($address_tags[$row['id']])) {
				$addr_desc_html .= ' ' . cereus_ipam_render_tag_badges($address_tags[$row['id']]);
			}
			form_selectable_cell($addr_desc_html, $row['id']);

			/* Color-coded state */
			$state_colors = array(
				'active'    => '#4CAF50',
				'reserved'  => '#2196F3',
				'dhcp'      => '#9C27B0',
				'offline'   => '#F44336',
				'available' => '#9E9E9E',
			);
			$color = $state_colors[$row['state']] ?? '#9E9E9E';
			form_selectable_cell('<span style="color:' . $color . ';">' . html_escape(ucfirst($row['state'])) . '</span>', $row['id']);

			form_selectable_cell(html_escape($row['mac_address'] ?? ''), $row['id']);
			form_selectable_cell(html_escape($row['owner'] ?? ''), $row['id']);

			/* Device link */
			$device_text = '';
			if (!empty($row['cacti_host_id']) && !empty($row['device_desc'])) {
				$status_class = ($row['device_status'] == 3) ? 'deviceUp' : 'deviceDown';
				$device_text = '<a href="' . html_escape($config['url_path']) . 'host.php?action=edit&id=' . $row['cacti_host_id'] . '">'
					. '<span class="' . $status_class . '">' . html_escape($row['device_desc']) . '</span></a>';
			}
			form_selectable_cell($device_text, $row['id']);

			form_selectable_cell(!empty($row['last_seen']) ? $row['last_seen'] : '', $row['id']);

			if (cereus_ipam_license_has_nat()) {
				form_selectable_cell(html_escape($row['nat_inside'] ?? ''), $row['id']);
				form_selectable_cell(html_escape($row['nat_outside'] ?? ''), $row['id']);
			}

			if (cereus_ipam_license_has_locations()) {
				$loc_name = '';
				if (!empty($row['location_id'])) {
					$loc_name = db_fetch_cell_prepared("SELECT name FROM plugin_cereus_ipam_locations WHERE id = ?", array($row['location_id']));
				}
				form_selectable_cell(html_escape($loc_name), $row['id']);
			}

			form_checkbox_cell($row['ip'], $row['id']);
			form_end_row();
		}
	} else {
		print '<tr><td colspan="9"><em>' . __('No addresses found. Click the + to add one.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box(false);
	print $nav;

	form_hidden_box('subnet_id', $subnet_id, '0');
	draw_actions_dropdown($actions);
	?>
	<script type='text/javascript'>
	$(function() {
		$('.cipam-ping-btn').click(function(e) {
			e.preventDefault();
			var btn = $(this);
			var ip = btn.data('ip');
			var resultSpan = btn.next('.cipam-ping-result');
			resultSpan.html('<i class="fa fa-spinner fa-spin" style="color:#999;"></i>');
			btn.css('pointer-events', 'none');
			$.getJSON('cereus_ipam_addresses.php?action=ping&ip=' + encodeURIComponent(ip), function(data) {
				if (data.alive) {
					var info = data.latency || 'alive';
					if (data.method) info += ' [' + data.method + ']';
					resultSpan.html('<span style="color:#4CAF50;">&#10003; ' + info + '</span>');
				} else {
					resultSpan.html('<span style="color:#F44336;">&#10007; down</span>');
				}
			}).fail(function() {
				resultSpan.html('<span style="color:#999;">?</span>');
			}).always(function() {
				btn.css('pointer-events', '');
			});
		});
	});
	</script>
	<?php
}

/* ==================== Fill Range Form ==================== */

function cereus_ipam_address_fill_range_form() {
	global $cereus_ipam_states;

	$subnet_id = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);

	if (!$subnet_id) {
		raise_message('cereus_ipam_nosub', __('No subnet selected.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam.php');
		exit;
	}

	$subnet = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
	if (!cacti_sizeof($subnet)) {
		raise_message('cereus_ipam_nf', __('Subnet not found.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam.php');
		exit;
	}

	/* RBAC check */
	$section_id = db_fetch_cell_prepared("SELECT section_id FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
	if ($section_id && !cereus_ipam_check_section_permission($section_id, 'edit')) {
		raise_message('cereus_ipam_perm', __('You do not have permission to edit addresses in this section.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_addresses.php?subnet_id=' . $subnet_id);
		exit;
	}

	$subnet_label = html_escape($subnet['subnet']) . '/' . $subnet['mask'];
	$next_ip = cereus_ipam_next_available($subnet_id);

	$fields = array(
		'fill_header' => array(
			'friendly_name' => __('Fill Range in Subnet %s', $subnet_label, 'cereus_ipam'),
			'method'        => 'spacer',
		),
		'start_ip' => array(
			'friendly_name' => __('Start IP', 'cereus_ipam'),
			'description'   => __('First IP address in the range to fill.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $next_ip ? $next_ip : '',
			'max_length'    => 45,
			'size'          => 40,
		),
		'end_ip' => array(
			'friendly_name' => __('End IP', 'cereus_ipam'),
			'description'   => __('Last IP address in the range to fill.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => '',
			'max_length'    => 45,
			'size'          => 40,
		),
		'state' => array(
			'friendly_name' => __('State', 'cereus_ipam'),
			'description'   => __('State to assign to all created addresses.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'value'         => 'available',
			'array'         => $cereus_ipam_states,
		),
		'owner' => array(
			'friendly_name' => __('Owner', 'cereus_ipam'),
			'description'   => __('Owner to assign to all created addresses.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => '',
			'max_length'    => 255,
			'size'          => 40,
		),
		'description' => array(
			'friendly_name' => __('Description', 'cereus_ipam'),
			'description'   => __('Description to assign to all created addresses.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => '',
			'max_length'    => 255,
			'size'          => 60,
		),
	);

	form_start('cereus_ipam_addresses.php');
	html_start_box(__('Fill IP Range', 'cereus_ipam'), '100%', '', '3', 'center', '');
	draw_edit_form(array(
		'config' => array('no_form_tag' => true),
		'fields' => $fields,
	));
	html_end_box();

	form_hidden_box('subnet_id', $subnet_id, '0');
	form_hidden_box('save_component', 'fill_range', '');
	form_save_button('cereus_ipam_addresses.php?subnet_id=' . $subnet_id, 'create');
}

/* ==================== Fill Range Save ==================== */

function cereus_ipam_address_fill_range_save() {
	$subnet_id   = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);
	$start_ip    = trim(get_nfilter_request_var('start_ip', ''));
	$end_ip      = trim(get_nfilter_request_var('end_ip', ''));
	$state       = get_nfilter_request_var('state', 'available');
	$owner       = cereus_ipam_sanitize_text(get_nfilter_request_var('owner', ''), 255);
	$description = cereus_ipam_sanitize_text(get_nfilter_request_var('description', ''), 255);

	if (!$subnet_id) {
		raise_message('cereus_ipam_nosub', __('No subnet selected.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam.php');
		exit;
	}

	/* RBAC check */
	$section_id = db_fetch_cell_prepared("SELECT section_id FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
	if ($section_id && !cereus_ipam_check_section_permission($section_id, 'edit')) {
		raise_message('cereus_ipam_perm', __('You do not have permission to edit addresses in this section.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_addresses.php?subnet_id=' . $subnet_id);
		exit;
	}

	$subnet = db_fetch_row_prepared("SELECT subnet, mask FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
	if (!cacti_sizeof($subnet)) {
		raise_message('cereus_ipam_nf', __('Subnet not found.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam.php');
		exit;
	}

	/* Validate IPs */
	if (!cereus_ipam_validate_ip($start_ip)) {
		raise_message('cereus_ipam_ip', __('Invalid start IP address.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_addresses.php?action=fill_range&subnet_id=' . $subnet_id);
		exit;
	}

	if (!cereus_ipam_validate_ip($end_ip)) {
		raise_message('cereus_ipam_ip', __('Invalid end IP address.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_addresses.php?action=fill_range&subnet_id=' . $subnet_id);
		exit;
	}

	/* Validate IPs are in subnet */
	if (!cereus_ipam_ip_in_subnet($start_ip, $subnet['subnet'], $subnet['mask'])) {
		raise_message('cereus_ipam_range', __('Start IP is not within the selected subnet.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_addresses.php?action=fill_range&subnet_id=' . $subnet_id);
		exit;
	}

	if (!cereus_ipam_ip_in_subnet($end_ip, $subnet['subnet'], $subnet['mask'])) {
		raise_message('cereus_ipam_range', __('End IP is not within the selected subnet.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_addresses.php?action=fill_range&subnet_id=' . $subnet_id);
		exit;
	}

	/* Validate state */
	if (!cereus_ipam_validate_state($state)) {
		$state = 'available';
	}

	/* Convert to GMP and iterate */
	$version  = cereus_ipam_ip_version($start_ip);
	$current  = cereus_ipam_ip_to_gmp($start_ip);
	$end_gmp  = cereus_ipam_ip_to_gmp($end_ip);

	if (gmp_cmp($current, $end_gmp) > 0) {
		raise_message('cereus_ipam_range', __('Start IP must be less than or equal to End IP.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_addresses.php?action=fill_range&subnet_id=' . $subnet_id);
		exit;
	}

	/* Safety limit: max 1024 addresses per fill */
	$range_size = gmp_sub($end_gmp, $current);
	if (gmp_cmp($range_size, gmp_init(1023)) > 0) {
		raise_message('cereus_ipam_range', __('Range too large. Maximum 1024 addresses per fill operation.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_addresses.php?action=fill_range&subnet_id=' . $subnet_id);
		exit;
	}

	$user_id = $_SESSION['sess_user_id'] ?? 0;
	$created = 0;
	$skipped = 0;

	while (gmp_cmp($current, $end_gmp) <= 0) {
		$ip = cereus_ipam_gmp_to_ip($current, $version);

		$exists = db_fetch_cell_prepared(
			"SELECT COUNT(*) FROM plugin_cereus_ipam_addresses WHERE subnet_id = ? AND ip = ?",
			array($subnet_id, $ip)
		);

		if (!$exists) {
			db_execute_prepared(
				"INSERT INTO plugin_cereus_ipam_addresses (subnet_id, ip, state, owner, description, created_by) VALUES (?, ?, ?, ?, ?, ?)",
				array($subnet_id, $ip, $state, $owner, $description, $user_id)
			);

			$new_id = db_fetch_insert_id();
			cereus_ipam_changelog_record('create', 'address', $new_id, null, array('ip' => $ip, 'subnet_id' => $subnet_id));
			$created++;
		} else {
			$skipped++;
		}

		$current = gmp_add($current, 1);
	}

	raise_message('cereus_ipam_fill',
		__('Fill Range complete: %d created, %d skipped (already exist).', $created, $skipped, 'cereus_ipam'),
		MESSAGE_LEVEL_INFO
	);

	header('Location: cereus_ipam_addresses.php?subnet_id=' . $subnet_id);
	exit;
}

/* ==================== Address History / Timeline ==================== */

function cereus_ipam_address_history() {
	$id        = get_filter_request_var('id');
	$subnet_id = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);

	if ($id <= 0) {
		raise_message('cereus_ipam_nf', __('No address specified.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_addresses.php?subnet_id=' . $subnet_id);
		exit;
	}

	$addr = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_addresses WHERE id = ?", array($id));
	if (!cacti_sizeof($addr)) {
		raise_message('cereus_ipam_nf', __('Address not found.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_addresses.php?subnet_id=' . $subnet_id);
		exit;
	}

	$subnet_id = $addr['subnet_id'];
	$subnet = db_fetch_row_prepared("SELECT subnet, mask FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
	$subnet_label = cacti_sizeof($subnet) ? (html_escape($subnet['subnet']) . '/' . $subnet['mask']) : __('Unknown', 'cereus_ipam');

	/* Query 1: changelog entries directly linked to this address by object_id */
	$entries_by_id = db_fetch_assoc_prepared(
		"SELECT cl.*, u.username
		FROM plugin_cereus_ipam_changelog cl
		LEFT JOIN user_auth u ON u.id = cl.user_id
		WHERE cl.object_type = 'address' AND cl.object_id = ?
		ORDER BY cl.created DESC",
		array($id)
	);

	/* Query 2: changelog entries where old_value or new_value JSON contains this IP */
	$like_val = '%"ip":"' . str_replace(array('%', '_'), array('\\%', '\\_'), $addr['ip']) . '"%';

	$entries_by_ip = db_fetch_assoc_prepared(
		"SELECT cl.*, u.username
		FROM plugin_cereus_ipam_changelog cl
		LEFT JOIN user_auth u ON u.id = cl.user_id
		WHERE cl.object_type = 'address'
		  AND (cl.old_value LIKE ? OR cl.new_value LIKE ?)
		ORDER BY cl.created DESC",
		array($like_val, $like_val)
	);

	/* Merge and deduplicate by changelog ID */
	$merged = array();
	if (cacti_sizeof($entries_by_id)) {
		foreach ($entries_by_id as $entry) {
			$merged[$entry['id']] = $entry;
		}
	}
	if (cacti_sizeof($entries_by_ip)) {
		foreach ($entries_by_ip as $entry) {
			if (!isset($merged[$entry['id']])) {
				$merged[$entry['id']] = $entry;
			}
		}
	}

	/* Sort by created DESC */
	usort($merged, function($a, $b) {
		return strcmp($b['created'], $a['created']);
	});

	/* ---- Header Box ---- */
	html_start_box(
		__('Address History: %s', html_escape($addr['ip']), 'cereus_ipam')
		. ' &mdash; ' . __('Subnet: %s', $subnet_label, 'cereus_ipam'),
		'100%', '', '3', 'center', ''
	);
	html_end_box();

	/* ---- Current State Summary ---- */
	html_start_box(__('Current State', 'cereus_ipam'), '100%', '', '3', 'center', '');

	$state_colors = array(
		'active'    => '#4CAF50',
		'reserved'  => '#2196F3',
		'dhcp'      => '#9C27B0',
		'offline'   => '#F44336',
		'available' => '#9E9E9E',
	);
	$state_color = $state_colors[$addr['state']] ?? '#9E9E9E';

	print '<tr class="even"><td style="padding:8px 15px;">';
	print '<table class="cactiTable" style="width:auto;">';
	print '<tr><td style="padding:2px 10px;"><b>' . __('IP Address', 'cereus_ipam') . ':</b></td><td>' . html_escape($addr['ip']) . '</td></tr>';
	print '<tr><td style="padding:2px 10px;"><b>' . __('Hostname', 'cereus_ipam') . ':</b></td><td>' . html_escape($addr['hostname'] ?? '') . '</td></tr>';
	print '<tr><td style="padding:2px 10px;"><b>' . __('State', 'cereus_ipam') . ':</b></td><td><span style="color:' . $state_color . ';font-weight:bold;">' . html_escape(ucfirst($addr['state'])) . '</span></td></tr>';
	print '<tr><td style="padding:2px 10px;"><b>' . __('MAC Address', 'cereus_ipam') . ':</b></td><td>' . html_escape($addr['mac_address'] ?? '') . '</td></tr>';
	print '<tr><td style="padding:2px 10px;"><b>' . __('Owner', 'cereus_ipam') . ':</b></td><td>' . html_escape($addr['owner'] ?? '') . '</td></tr>';
	print '<tr><td style="padding:2px 10px;"><b>' . __('Last Seen', 'cereus_ipam') . ':</b></td><td>' . html_escape($addr['last_seen'] ?? __('Never', 'cereus_ipam')) . '</td></tr>';
	print '</table>';
	print '</td></tr>';

	html_end_box();

	/* ---- Timeline Table ---- */
	html_start_box(__('Timeline', 'cereus_ipam') . ' (' . cacti_sizeof($merged) . ' ' . __('entries', 'cereus_ipam') . ')', '100%', '', '3', 'center', '');

	html_header(array(
		__('Date', 'cereus_ipam'),
		__('User', 'cereus_ipam'),
		__('Action', 'cereus_ipam'),
		__('Details', 'cereus_ipam'),
	));

	if (cacti_sizeof($merged)) {
		$action_styles = array(
			'create'   => 'background:#4CAF50;color:#fff;',
			'update'   => 'background:#2196F3;color:#fff;',
			'delete'   => 'background:#F44336;color:#fff;',
			'scan'     => 'background:#9C27B0;color:#fff;',
			'import'   => 'background:#FF9800;color:#fff;',
			'truncate' => 'background:#795548;color:#fff;',
		);

		foreach ($merged as $cl) {
			form_alternate_row();

			/* Date */
			form_selectable_cell(html_escape($cl['created']), $cl['id']);

			/* User */
			$username = !empty($cl['username']) ? html_escape($cl['username']) : __('System', 'cereus_ipam');
			form_selectable_cell($username, $cl['id']);

			/* Action badge */
			$badge_style = $action_styles[$cl['action']] ?? 'background:#607D8B;color:#fff;';
			$badge = '<span style="' . $badge_style . 'padding:2px 8px;border-radius:3px;font-size:11px;">'
				. html_escape(ucfirst($cl['action'])) . '</span>';
			form_selectable_cell($badge, $cl['id']);

			/* Details: parse old_value / new_value JSON */
			$old = !empty($cl['old_value']) ? json_decode($cl['old_value'], true) : null;
			$new = !empty($cl['new_value']) ? json_decode($cl['new_value'], true) : null;
			$details = '';

			switch ($cl['action']) {
				case 'create':
					if (is_array($new)) {
						$parts = array();
						foreach ($new as $field => $val) {
							if ($val !== '' && $val !== null) {
								$parts[] = '<b>' . html_escape($field) . '</b>: ' . html_escape($val);
							}
						}
						$details = __('Created with: ', 'cereus_ipam') . implode(', ', $parts);
					} else {
						$details = __('Address created.', 'cereus_ipam');
					}
					break;

				case 'update':
					if (is_array($old) && is_array($new)) {
						/* Show field-by-field diff */
						$all_keys = array_unique(array_merge(array_keys($old), array_keys($new)));
						$changes = array();
						foreach ($all_keys as $field) {
							$old_val = isset($old[$field]) ? (string) $old[$field] : '';
							$new_val = isset($new[$field]) ? (string) $new[$field] : '';
							if ($old_val !== $new_val) {
								$changes[] = '<b>' . html_escape($field) . '</b>: '
									. '<span style="text-decoration:line-through;color:#999;">' . html_escape($old_val) . '</span>'
									. ' &rarr; ' . html_escape($new_val);
							}
						}
						if (cacti_sizeof($changes)) {
							$details = implode('<br>', $changes);
						} else {
							$details = __('Updated (no field differences detected).', 'cereus_ipam');
						}
					} elseif (is_array($old)) {
						$parts = array();
						foreach ($old as $field => $val) {
							$parts[] = '<b>' . html_escape($field) . '</b>: ' . html_escape($val);
						}
						$details = __('Previous values: ', 'cereus_ipam') . implode(', ', $parts);
					} else {
						$details = __('Updated.', 'cereus_ipam');
					}
					break;

				case 'delete':
					if (is_array($old)) {
						$parts = array();
						foreach ($old as $field => $val) {
							if ($val !== '' && $val !== null) {
								$parts[] = '<b>' . html_escape($field) . '</b>: ' . html_escape($val);
							}
						}
						$details = __('Deleted. Previous values: ', 'cereus_ipam') . implode(', ', $parts);
					} else {
						$details = __('Address deleted.', 'cereus_ipam');
					}
					break;

				case 'scan':
					if (is_array($new)) {
						$parts = array();
						foreach ($new as $field => $val) {
							$parts[] = '<b>' . html_escape($field) . '</b>: ' . html_escape($val);
						}
						$details = __('Scan result: ', 'cereus_ipam') . implode(', ', $parts);
					} else {
						$details = __('Scanned.', 'cereus_ipam');
					}
					break;

				case 'import':
					if (is_array($new)) {
						$parts = array();
						foreach ($new as $field => $val) {
							if ($val !== '' && $val !== null) {
								$parts[] = '<b>' . html_escape($field) . '</b>: ' . html_escape($val);
							}
						}
						$details = __('Imported with: ', 'cereus_ipam') . implode(', ', $parts);
					} else {
						$details = __('Imported.', 'cereus_ipam');
					}
					break;

				default:
					$details = '';
					if (is_array($old)) {
						$details .= __('Old: ', 'cereus_ipam') . html_escape(json_encode($old));
					}
					if (is_array($new)) {
						$details .= ($details ? '<br>' : '') . __('New: ', 'cereus_ipam') . html_escape(json_encode($new));
					}
					if (empty($details)) {
						$details = html_escape($cl['action']);
					}
					break;
			}

			form_selectable_cell($details, $cl['id'], '', 'white-space:normal;');
			form_end_row();
		}
	} else {
		print '<tr><td colspan="4"><em>' . __('No history entries found for this address.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box(false);

	/* Back link */
	print '<div style="padding:10px 0;">';
	print '<a class="linkEditMain" href="cereus_ipam_addresses.php?subnet_id=' . $subnet_id . '">'
		. '&laquo; ' . __('Back to Addresses', 'cereus_ipam') . '</a>';
	print '</div>';
}

/* ==================== Visual IP Address Grid ==================== */

function cereus_ipam_address_visual() {
	global $config;

	$subnet_id = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);

	if (!$subnet_id) {
		raise_message('cereus_ipam_nosub', __('No subnet selected.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam.php');
		exit;
	}

	/* License gate: Professional+ for visual map */
	if (!cereus_ipam_license_has_visual_map()) {
		html_start_box(__('Visual Network Map', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr><td class="center" style="padding:40px;">';
		print '<i class="fa fa-lock" style="font-size:48px;color:#ccc;"></i><br><br>';
		print '<span style="font-size:16px;color:#666;">' . __('Visual Network Map requires a Professional license.', 'cereus_ipam') . '</span><br><br>';
		print '<a href="https://www.urban-software.com/products/cereus-ipam/" class="ui-button" target="_blank">' . __('Upgrade', 'cereus_ipam') . '</a>';
		print ' <input type="button" class="ui-button" value="' . __esc('Back', 'cereus_ipam') . '" onclick="document.location=\'cereus_ipam_addresses.php?subnet_id=' . (int) $subnet_id . '\'">';
		print '</td></tr>';
		html_end_box();
		return;
	}

	$subnet = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
	if (!cacti_sizeof($subnet)) {
		raise_message('cereus_ipam_nf', __('Subnet not found.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam.php');
		exit;
	}

	$version = cereus_ipam_ip_version($subnet['subnet']);
	$mask    = (int) $subnet['mask'];

	if ($version != 4 || $mask < 16) {
		raise_message('cereus_ipam_visual_unsupported', __('Visual map is only available for IPv4 subnets /16 to /32.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_addresses.php?subnet_id=' . $subnet_id);
		exit;
	}

	$util = cereus_ipam_subnet_utilization($subnet_id);
	$has_hilbert = cereus_ipam_license_has_hilbert_map();
	$is_large = ($mask < 22); /* /16-/21: show tile overview first */

	/* Include d3.js */
	print '<script src="' . html_escape($config['url_path']) . 'include/js/d3.js"></script>';

	/* Header box with controls */
	html_start_box(
		__('Visual Map: %s/%s', html_escape($subnet['subnet']), $mask, 'cereus_ipam')
		. ' (' . $util['used'] . '/' . $util['total'] . ' ' . __('used', 'cereus_ipam') . ')',
		'100%', '', '3', 'center', ''
	);
	?>
	<tr class='even'>
		<td style='padding:8px;'>
			<input type='button' class='ui-button' id='table_view' value='<?php print __esc('Table View', 'cereus_ipam'); ?>'>
			<input type='button' class='ui-button ui-button-active' id='btn_tilemap' value='<?php print __esc('Tile Map', 'cereus_ipam'); ?>' style='margin-left:5px;'>
			<?php if ($has_hilbert) { ?>
			<input type='button' class='ui-button' id='btn_hilbert' value='<?php print __esc('Hilbert Heatmap', 'cereus_ipam'); ?>' style='margin-left:5px;'>
			<?php } else { ?>
			<input type='button' class='ui-button' id='btn_hilbert' value='<?php print __esc('Hilbert Heatmap', 'cereus_ipam'); ?>' style='margin-left:5px;opacity:0.5;' disabled title='<?php print __esc('Hilbert Heatmap requires an Enterprise license.', 'cereus_ipam'); ?>'>
			<?php } ?>
			<?php if ($is_large) { ?>
			<input type='button' class='ui-button' id='btn_back_overview' value='<?php print __esc('Back to Overview', 'cereus_ipam'); ?>' style='margin-left:10px;display:none;'>
			<?php } ?>
			<input type='button' class='ui-button' id='btn_export_png' value='<?php print __esc('Export PNG', 'cereus_ipam'); ?>' style='margin-left:10px;'>
			<span style='margin-left:20px;' id='cipam_legend'>
				<span style='display:inline-block;width:12px;height:12px;background:#4CAF50;border-radius:2px;vertical-align:middle;'></span> <?php print __('Active', 'cereus_ipam'); ?>
				<span style='display:inline-block;width:12px;height:12px;background:#2196F3;border-radius:2px;vertical-align:middle;margin-left:8px;'></span> <?php print __('Reserved', 'cereus_ipam'); ?>
				<span style='display:inline-block;width:12px;height:12px;background:#9C27B0;border-radius:2px;vertical-align:middle;margin-left:8px;'></span> <?php print __('DHCP', 'cereus_ipam'); ?>
				<span style='display:inline-block;width:12px;height:12px;background:#F44336;border-radius:2px;vertical-align:middle;margin-left:8px;'></span> <?php print __('Offline', 'cereus_ipam'); ?>
				<span style='display:inline-block;width:12px;height:12px;background:#E0E0E0;border-radius:2px;vertical-align:middle;margin-left:8px;border:1px solid #bbb;'></span> <?php print __('Available', 'cereus_ipam'); ?>
				<span style='display:inline-block;width:12px;height:12px;background:#FF9800;border-radius:2px;vertical-align:middle;margin-left:8px;'></span> <?php print __('Conflict', 'cereus_ipam'); ?>
			</span>
		</td>
	</tr>
	<?php
	html_end_box();

	/* Tooltip container (shared by all views) */
	print '<div id="cipam_tooltip" style="position:fixed;display:none;background:#333;color:#fff;padding:8px 12px;border-radius:4px;font-size:12px;pointer-events:none;z-index:10000;max-width:350px;box-shadow:0 2px 8px rgba(0,0,0,0.3);"></div>';

	/* Map container */
	html_start_box('', '100%', '', '3', 'center', '');
	print '<tr><td style="padding:10px;">';
	print '<div id="cipam_map_container" style="min-height:200px;position:relative;"></div>';
	print '<div id="cipam_loading" style="text-align:center;padding:40px;color:#999;"><i class="fa fa-spinner fa-spin fa-2x"></i><br>' . __('Loading...', 'cereus_ipam') . '</div>';
	print '</td></tr>';
	html_end_box();

	/* Embed the full d3.js visual map JavaScript */
	?>
	<script type='text/javascript'>
	$(function() {
		var subnetId = <?php print (int) $subnet_id; ?>;
		var subnetCidr = '<?php print html_escape($subnet['subnet'] . '/' . $mask); ?>';
		var mask = <?php print (int) $mask; ?>;
		var isLarge = <?php print $is_large ? 'true' : 'false'; ?>;
		var hasHilbert = <?php print $has_hilbert ? 'true' : 'false'; ?>;
		var currentView = 'tilemap'; /* tilemap | hilbert */
		var drilledBlock = null; /* current /24 block when drilled in */

		var stateColors = {
			'active':    '#4CAF50',
			'reserved':  '#2196F3',
			'dhcp':      '#9C27B0',
			'offline':   '#F44336',
			'available': '#E0E0E0',
			'conflict':  '#FF9800'
		};

		/* Utilization gradient: 0% = #E0E0E0 (gray) → green → yellow → orange → red at 100% */
		function utilColor(pct) {
			if (pct <= 0) return '#E0E0E0';
			if (pct <= 50) {
				var t = pct / 50;
				return d3.interpolateRgb('#4CAF50', '#FFC107')(t);
			}
			var t2 = (pct - 50) / 50;
			return d3.interpolateRgb('#FFC107', '#F44336')(t2);
		}

		var $container = $('#cipam_map_container');
		var $loading = $('#cipam_loading');
		var $tooltip = $('#cipam_tooltip');

		function showTooltip(html, event) {
			$tooltip.html(html).css({
				left: Math.min(event.clientX + 12, window.innerWidth - 370) + 'px',
				top: (event.clientY + 12) + 'px',
				display: 'block'
			});
		}
		function hideTooltip() { $tooltip.hide(); }

		/* ========== Data loading ========== */

		function loadOverviewData(callback) {
			$.ajax({
				url: 'cereus_ipam_addresses.php',
				data: { action: 'visual_data', subnet_id: subnetId },
				dataType: 'json',
				success: function(data) { $loading.hide(); callback(data); },
				error: function() { $loading.html('<span style="color:#F44336;">Failed to load data.</span>'); }
			});
		}

		function loadChunkData(blockPrefix, callback) {
			$.ajax({
				url: 'cereus_ipam_addresses.php',
				data: { action: 'visual_data_chunk', subnet_id: subnetId, block: blockPrefix },
				dataType: 'json',
				success: function(data) { callback(data); },
				error: function() { $container.html('<span style="color:#F44336;">Failed to load block data.</span>'); }
			});
		}

		/* ========== Tile Map: /24 overview for large subnets ========== */

		function renderTileOverview(data) {
			$container.empty();
			drilledBlock = null;
			$('#btn_back_overview').hide();

			var blocks = data.summary_24 || [];
			if (!blocks.length) {
				$container.html('<div style="text-align:center;padding:40px;color:#999;"><?php print __esc('No /24 blocks found.', 'cereus_ipam'); ?></div>');
				return;
			}

			/* Determine grid: /16 = 256 blocks (16x16), /20 = 16 blocks (4x4), etc. */
			var count = blocks.length;
			var cols = Math.ceil(Math.sqrt(count));
			if (cols > 16) cols = 16;
			var tileSize = Math.max(32, Math.min(60, Math.floor(900 / cols)));
			var gap = 3;

			var svg = d3.select('#cipam_map_container').append('svg')
				.attr('width', cols * (tileSize + gap))
				.attr('height', Math.ceil(count / cols) * (tileSize + gap))
				.attr('id', 'cipam_svg');

			var tiles = svg.selectAll('g').data(blocks).enter().append('g')
				.attr('transform', function(d, i) {
					var x = (i % cols) * (tileSize + gap);
					var y = Math.floor(i / cols) * (tileSize + gap);
					return 'translate(' + x + ',' + y + ')';
				})
				.style('cursor', 'pointer');

			tiles.append('rect')
				.attr('width', tileSize)
				.attr('height', tileSize)
				.attr('rx', 3)
				.attr('fill', function(d) { return utilColor(d.pct); })
				.attr('stroke', '#999')
				.attr('stroke-width', 0.5);

			/* Label: third octet */
			tiles.append('text')
				.attr('x', tileSize / 2)
				.attr('y', tileSize / 2 - 2)
				.attr('text-anchor', 'middle')
				.attr('dominant-baseline', 'middle')
				.attr('font-size', Math.max(8, tileSize / 5) + 'px')
				.attr('font-weight', 'bold')
				.attr('fill', function(d) { return d.pct > 60 ? '#fff' : '#333'; })
				.attr('pointer-events', 'none')
				.text(function(d) {
					var parts = d.prefix.split('.');
					return '.' + parts[2] + '.x';
				});

			/* Pct label below */
			tiles.append('text')
				.attr('x', tileSize / 2)
				.attr('y', tileSize / 2 + Math.max(8, tileSize / 5))
				.attr('text-anchor', 'middle')
				.attr('font-size', Math.max(7, tileSize / 6) + 'px')
				.attr('fill', function(d) { return d.pct > 60 ? 'rgba(255,255,255,0.8)' : '#666'; })
				.attr('pointer-events', 'none')
				.text(function(d) { return d.pct + '%'; });

			tiles.on('mouseover', function(event, d) {
				d3.select(this).select('rect').attr('stroke', '#333').attr('stroke-width', 2);
				var html = '<strong>' + d.prefix + '/24</strong><br>'
					+ '<?php print __esc('Utilization', 'cereus_ipam'); ?>: ' + d.pct + '%<br>'
					+ '<span style="color:#4CAF50;">●</span> ' + d.active + ' '
					+ '<span style="color:#2196F3;">●</span> ' + d.reserved + ' '
					+ '<span style="color:#9C27B0;">●</span> ' + d.dhcp + ' '
					+ '<span style="color:#F44336;">●</span> ' + d.offline + ' '
					+ '<span style="color:#bbb;">●</span> ' + (256 - d.used) + ' <?php print __esc('free', 'cereus_ipam'); ?>';
				showTooltip(html, event);
			})
			.on('mousemove', function(event) {
				$tooltip.css({ left: Math.min(event.clientX + 12, window.innerWidth - 370) + 'px', top: (event.clientY + 12) + 'px' });
			})
			.on('mouseout', function() {
				d3.select(this).select('rect').attr('stroke', '#999').attr('stroke-width', 0.5);
				hideTooltip();
			})
			.on('click', function(event, d) {
				hideTooltip();
				drillIntoBlock(d.prefix);
			});
		}

		/* ========== Tile Map: per-IP grid (for /24 or drill-down) ========== */

		function renderIpGrid(addresses, blockPrefix) {
			$container.empty();
			drilledBlock = blockPrefix || null;

			if (isLarge && blockPrefix) {
				$('#btn_back_overview').show();
			}

			var total = addresses.length;
			if (!total) {
				$container.html('<div style="text-align:center;padding:40px;color:#999;"><?php print __esc('No addresses in this block.', 'cereus_ipam'); ?></div>');
				return;
			}

			var cols = 16;
			if (total <= 16) cols = total;
			else if (total <= 64) cols = 8;

			var blockSize = (total <= 64) ? 36 : ((total <= 256) ? 28 : 22);
			var gap = 2;

			var svg = d3.select('#cipam_map_container').append('svg')
				.attr('width', cols * (blockSize + gap) + gap)
				.attr('height', Math.ceil(total / cols) * (blockSize + gap) + gap)
				.attr('id', 'cipam_svg');

			var blocks = svg.selectAll('g').data(addresses).enter().append('g')
				.attr('transform', function(d, i) {
					var x = (i % cols) * (blockSize + gap) + gap;
					var y = Math.floor(i / cols) * (blockSize + gap) + gap;
					return 'translate(' + x + ',' + y + ')';
				})
				.style('cursor', 'pointer');

			blocks.append('rect')
				.attr('width', blockSize)
				.attr('height', blockSize)
				.attr('rx', 3)
				.attr('fill', function(d) { return stateColors[d.state] || '#E0E0E0'; })
				.attr('stroke', 'rgba(0,0,0,0.1)')
				.attr('stroke-width', 0.5);

			/* Last octet label */
			blocks.append('text')
				.attr('x', blockSize / 2)
				.attr('y', blockSize / 2 + 1)
				.attr('text-anchor', 'middle')
				.attr('dominant-baseline', 'middle')
				.attr('font-size', (blockSize >= 28 ? 10 : 8) + 'px')
				.attr('font-weight', 'bold')
				.attr('fill', function(d) { return d.state === 'available' ? '#999' : '#fff'; })
				.attr('pointer-events', 'none')
				.attr('style', function(d) { return d.state === 'available' ? '' : 'text-shadow:0 0 2px rgba(0,0,0,0.4)'; })
				.text(function(d) { return d.ip.split('.').pop(); });

			blocks.on('mouseover', function(event, d) {
				d3.select(this).select('rect').attr('stroke', '#333').attr('stroke-width', 2);
				var html = '<strong>' + d.ip + '</strong>';
				if (d.hostname) html += '<br>' + d.hostname;
				if (d.mac) html += '<br>' + d.mac;
				if (d.owner) html += '<br>' + d.owner;
				html += '<br><em>' + d.state.charAt(0).toUpperCase() + d.state.slice(1) + '</em>';
				showTooltip(html, event);
			})
			.on('mousemove', function(event) {
				$tooltip.css({ left: Math.min(event.clientX + 12, window.innerWidth - 370) + 'px', top: (event.clientY + 12) + 'px' });
			})
			.on('mouseout', function() {
				d3.select(this).select('rect').attr('stroke', 'rgba(0,0,0,0.1)').attr('stroke-width', 0.5);
				hideTooltip();
			})
			.on('click', function(event, d) {
				hideTooltip();
				if (d.id && d.id > 0) {
					document.location = 'cereus_ipam_addresses.php?action=edit&id=' + d.id + '&subnet_id=' + subnetId;
				} else {
					document.location = 'cereus_ipam_addresses.php?action=edit&id=0&subnet_id=' + subnetId + '&prefill_ip=' + encodeURIComponent(d.ip);
				}
			});
		}

		function drillIntoBlock(prefix) {
			$container.html('<div style="text-align:center;padding:20px;color:#999;"><i class="fa fa-spinner fa-spin"></i> <?php print __esc('Loading...', 'cereus_ipam'); ?></div>');
			loadChunkData(prefix, function(data) {
				if (currentView === 'hilbert' && hasHilbert) {
					renderHilbert(data.addresses || [], prefix);
				} else {
					renderIpGrid(data.addresses || [], prefix);
				}
			});
		}

		/* ========== Hilbert Curve Heatmap (Enterprise) ========== */

		/* Convert linear index d to (x,y) on a Hilbert curve of order n */
		function hilbertD2XY(n, d) {
			var x = 0, y = 0, s, rx, ry, t = d;
			for (s = 1; s < n; s *= 2) {
				rx = 1 & (Math.floor(t / 2));
				ry = 1 & (t ^ rx);
				if (ry === 0) {
					if (rx === 1) { x = s - 1 - x; y = s - 1 - y; }
					var tmp = x; x = y; y = tmp;
				}
				x += s * rx;
				y += s * ry;
				t = Math.floor(t / 4);
			}
			return { x: x, y: y };
		}

		function renderHilbert(addresses, blockPrefix) {
			$container.empty();
			drilledBlock = blockPrefix || null;

			if (isLarge && blockPrefix) {
				$('#btn_back_overview').show();
			} else if (isLarge && !blockPrefix) {
				$('#btn_back_overview').hide();
			}

			var total = addresses.length;
			if (!total) {
				$container.html('<div style="text-align:center;padding:40px;color:#999;"><?php print __esc('No addresses.', 'cereus_ipam'); ?></div>');
				return;
			}

			/* Hilbert order: smallest power of 2 that fits total */
			var order = 1;
			while (order * order < total) order *= 2;

			/* Cell size adapts: large for /24 (256 IPs → 16x16), small for /16 (65536 → 256x256) */
			var cellSize;
			if (total <= 256) cellSize = 28;
			else if (total <= 1024) cellSize = 14;
			else if (total <= 4096) cellSize = 7;
			else cellSize = 3;

			var svgSize = order * cellSize;

			/* Build lookup map for fast access */
			var addrLookup = {};
			addresses.forEach(function(a, i) { addrLookup[i] = a; });

			/* Use canvas for large datasets (>1024 IPs) for performance */
			if (total > 1024) {
				var canvas = document.createElement('canvas');
				canvas.id = 'cipam_hilbert_canvas';
				canvas.width = svgSize;
				canvas.height = svgSize;
				canvas.style.cursor = 'crosshair';
				canvas.style.border = '1px solid #ddd';
				canvas.style.borderRadius = '4px';
				$container.append(canvas);

				var ctx = canvas.getContext('2d');
				ctx.fillStyle = '#E0E0E0';
				ctx.fillRect(0, 0, svgSize, svgSize);

				/* Render all cells */
				for (var i = 0; i < total; i++) {
					var pos = hilbertD2XY(order, i);
					var a = addrLookup[i];
					ctx.fillStyle = a ? (stateColors[a.state] || '#E0E0E0') : '#E0E0E0';
					ctx.fillRect(pos.x * cellSize, pos.y * cellSize, cellSize, cellSize);
				}

				/* Grid lines for larger cells */
				if (cellSize >= 5) {
					ctx.strokeStyle = 'rgba(0,0,0,0.05)';
					ctx.lineWidth = 0.5;
					for (var i = 0; i < total; i++) {
						var pos = hilbertD2XY(order, i);
						ctx.strokeRect(pos.x * cellSize, pos.y * cellSize, cellSize, cellSize);
					}
				}

				/* Mouse interaction on canvas */
				$(canvas).on('mousemove', function(event) {
					var rect = canvas.getBoundingClientRect();
					var mx = event.clientX - rect.left;
					var my = event.clientY - rect.top;
					var gx = Math.floor(mx / cellSize);
					var gy = Math.floor(my / cellSize);

					/* Reverse: find index from (x,y) via brute scan for small, or xy2d for perf */
					var idx = hilbertXY2D(order, gx, gy);
					if (idx >= 0 && idx < total && addrLookup[idx]) {
						var d = addrLookup[idx];
						var html = '<strong>' + d.ip + '</strong>';
						if (d.hostname) html += '<br>' + d.hostname;
						if (d.mac) html += '<br>' + d.mac;
						html += '<br><em>' + d.state.charAt(0).toUpperCase() + d.state.slice(1) + '</em>';
						showTooltip(html, event);
					} else {
						hideTooltip();
					}
				}).on('mouseout', function() {
					hideTooltip();
				}).on('click', function(event) {
					var rect = canvas.getBoundingClientRect();
					var mx = event.clientX - rect.left;
					var my = event.clientY - rect.top;
					var gx = Math.floor(mx / cellSize);
					var gy = Math.floor(my / cellSize);
					var idx = hilbertXY2D(order, gx, gy);
					if (idx >= 0 && idx < total && addrLookup[idx]) {
						var d = addrLookup[idx];
						hideTooltip();
						if (d.id && d.id > 0) {
							document.location = 'cereus_ipam_addresses.php?action=edit&id=' + d.id + '&subnet_id=' + subnetId;
						} else {
							document.location = 'cereus_ipam_addresses.php?action=edit&id=0&subnet_id=' + subnetId + '&prefill_ip=' + encodeURIComponent(d.ip);
						}
					}
				});
			} else {
				/* SVG for small datasets — better interaction */
				var svg = d3.select('#cipam_map_container').append('svg')
					.attr('width', svgSize)
					.attr('height', svgSize)
					.attr('id', 'cipam_svg')
					.style('border', '1px solid #ddd')
					.style('border-radius', '4px');

				var cellData = [];
				for (var i = 0; i < total; i++) {
					var pos = hilbertD2XY(order, i);
					cellData.push({ idx: i, x: pos.x, y: pos.y, addr: addrLookup[i] || null });
				}

				var cells = svg.selectAll('rect').data(cellData).enter().append('rect')
					.attr('x', function(d) { return d.x * cellSize; })
					.attr('y', function(d) { return d.y * cellSize; })
					.attr('width', cellSize)
					.attr('height', cellSize)
					.attr('fill', function(d) { return d.addr ? (stateColors[d.addr.state] || '#E0E0E0') : '#E0E0E0'; })
					.attr('stroke', 'rgba(0,0,0,0.05)')
					.attr('stroke-width', 0.5)
					.style('cursor', 'pointer');

				cells.on('mouseover', function(event, d) {
					if (!d.addr) return;
					d3.select(this).attr('stroke', '#333').attr('stroke-width', 2);
					var html = '<strong>' + d.addr.ip + '</strong>';
					if (d.addr.hostname) html += '<br>' + d.addr.hostname;
					if (d.addr.mac) html += '<br>' + d.addr.mac;
					html += '<br><em>' + d.addr.state.charAt(0).toUpperCase() + d.addr.state.slice(1) + '</em>';
					showTooltip(html, event);
				})
				.on('mousemove', function(event) {
					$tooltip.css({ left: Math.min(event.clientX + 12, window.innerWidth - 370) + 'px', top: (event.clientY + 12) + 'px' });
				})
				.on('mouseout', function() {
					d3.select(this).attr('stroke', 'rgba(0,0,0,0.05)').attr('stroke-width', 0.5);
					hideTooltip();
				})
				.on('click', function(event, d) {
					if (!d.addr) return;
					hideTooltip();
					if (d.addr.id && d.addr.id > 0) {
						document.location = 'cereus_ipam_addresses.php?action=edit&id=' + d.addr.id + '&subnet_id=' + subnetId;
					} else {
						document.location = 'cereus_ipam_addresses.php?action=edit&id=0&subnet_id=' + subnetId + '&prefill_ip=' + encodeURIComponent(d.addr.ip);
					}
				});
			}
		}

		/* Reverse Hilbert: (x,y) → index d */
		function hilbertXY2D(n, x, y) {
			var d = 0, s, rx, ry;
			for (s = n / 2; s > 0; s = Math.floor(s / 2)) {
				rx = (x & s) > 0 ? 1 : 0;
				ry = (y & s) > 0 ? 1 : 0;
				d += s * s * ((3 * rx) ^ ry);
				/* Rotate */
				if (ry === 0) {
					if (rx === 1) { x = s - 1 - x; y = s - 1 - y; }
					var tmp = x; x = y; y = tmp;
				}
			}
			return d;
		}

		/* ========== PNG Export ========== */

		$('#btn_export_png').click(function() {
			var svg = document.getElementById('cipam_svg');
			var canvas = document.getElementById('cipam_hilbert_canvas');

			if (canvas) {
				/* Already a canvas — direct export */
				var link = document.createElement('a');
				link.download = 'ipam_visual_' + subnetCidr.replace(/\//g, '_') + '.png';
				link.href = canvas.toDataURL('image/png');
				link.click();
			} else if (svg) {
				/* Convert SVG to canvas then PNG */
				var svgData = new XMLSerializer().serializeToString(svg);
				var img = new Image();
				var svgBlob = new Blob([svgData], { type: 'image/svg+xml;charset=utf-8' });
				var url = URL.createObjectURL(svgBlob);
				img.onload = function() {
					var c = document.createElement('canvas');
					c.width = svg.getAttribute('width');
					c.height = svg.getAttribute('height');
					var ctx = c.getContext('2d');
					ctx.fillStyle = '#fff';
					ctx.fillRect(0, 0, c.width, c.height);
					ctx.drawImage(img, 0, 0);
					URL.revokeObjectURL(url);
					var link = document.createElement('a');
					link.download = 'ipam_visual_' + subnetCidr.replace(/\//g, '_') + '.png';
					link.href = c.toDataURL('image/png');
					link.click();
				};
				img.src = url;
			}
		});

		/* ========== View switching ========== */

		$('#table_view').click(function() {
			document.location = 'cereus_ipam_addresses.php?subnet_id=' + subnetId;
		});

		$('#btn_tilemap').click(function() {
			if (currentView === 'tilemap') return;
			currentView = 'tilemap';
			$('#btn_tilemap').addClass('ui-button-active');
			$('#btn_hilbert').removeClass('ui-button-active');
			refreshView();
		});

		$('#btn_hilbert').click(function() {
			if (!hasHilbert || currentView === 'hilbert') return;
			currentView = 'hilbert';
			$('#btn_hilbert').addClass('ui-button-active');
			$('#btn_tilemap').removeClass('ui-button-active');
			refreshView();
		});

		$('#btn_back_overview').click(function() {
			drilledBlock = null;
			$loading.show();
			loadOverviewData(function(data) {
				if (currentView === 'hilbert' && hasHilbert) {
					/* Hilbert overview loads full dataset */
					renderHilbertOverview(data);
				} else {
					renderTileOverview(data);
				}
			});
		});

		function renderHilbertOverview(data) {
			if (isLarge) {
				/* For /16+: load all addresses progressively for Hilbert */
				$container.html('<div style="text-align:center;padding:20px;color:#999;"><i class="fa fa-spinner fa-spin"></i> <?php print __esc('Loading full dataset for Hilbert view...', 'cereus_ipam'); ?></div>');
				$.ajax({
					url: 'cereus_ipam_addresses.php',
					data: { action: 'visual_data', subnet_id: subnetId, full: 1 },
					dataType: 'json',
					success: function(fullData) {
						renderHilbert(fullData.addresses || [], null);
					}
				});
			} else {
				renderHilbert(data.addresses || [], null);
			}
		}

		function refreshView() {
			$loading.show();
			$container.empty();

			if (drilledBlock) {
				drillIntoBlock(drilledBlock);
				return;
			}

			loadOverviewData(function(data) {
				if (currentView === 'hilbert' && hasHilbert) {
					renderHilbertOverview(data);
				} else if (isLarge) {
					renderTileOverview(data);
				} else {
					renderIpGrid(data.addresses || [], null);
				}
			});
		}

		/* ========== Initial load ========== */
		refreshView();
	});
	</script>
	<?php
}

/* ========== AJAX: Visual map data (overview) ========== */

function cereus_ipam_address_visual_data() {
	$subnet_id = (int) get_nfilter_request_var('subnet_id');
	$full = (int) get_nfilter_request_var('full');

	header('Content-Type: application/json');

	if (!$subnet_id) {
		print json_encode(array('error' => 'Invalid subnet'));
		exit;
	}

	$subnet = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
	if (!cacti_sizeof($subnet)) {
		print json_encode(array('error' => 'Subnet not found'));
		exit;
	}

	$mask = (int) $subnet['mask'];
	$is_large = ($mask < 22);

	$result = array(
		'subnet'  => $subnet['subnet'] . '/' . $mask,
		'mask'    => $mask,
	);

	if ($is_large && !$full) {
		/* Return per-/24 summary blocks for overview */
		$addresses = db_fetch_assoc_prepared(
			"SELECT ip, state FROM plugin_cereus_ipam_addresses WHERE subnet_id = ?",
			array($subnet_id)
		);

		$block_counts = array();
		if (cacti_sizeof($addresses)) {
			foreach ($addresses as $a) {
				$octets = explode('.', $a['ip']);
				$bk = $octets[0] . '.' . $octets[1] . '.' . $octets[2] . '.0';
				if (!isset($block_counts[$bk])) {
					$block_counts[$bk] = array('used' => 0, 'active' => 0, 'reserved' => 0, 'dhcp' => 0, 'offline' => 0);
				}
				$block_counts[$bk]['used']++;
				$st = $a['state'];
				if (isset($block_counts[$bk][$st])) {
					$block_counts[$bk][$st]++;
				}
			}
		}

		/* Build ordered /24 block list */
		$range = cereus_ipam_cidr_to_range($subnet['subnet'], $mask);
		$start = cereus_ipam_ip_to_gmp($range['first']);
		$end   = cereus_ipam_ip_to_gmp($range['last']);
		$step  = gmp_init(256);

		$summary = array();
		$current = $start;
		while (gmp_cmp($current, $end) <= 0) {
			$bip = cereus_ipam_gmp_to_ip($current, 4);
			$c = $block_counts[$bip] ?? array('used' => 0, 'active' => 0, 'reserved' => 0, 'dhcp' => 0, 'offline' => 0);
			$summary[] = array(
				'prefix'   => $bip,
				'used'     => $c['used'],
				'active'   => $c['active'],
				'reserved' => $c['reserved'],
				'dhcp'     => $c['dhcp'],
				'offline'  => $c['offline'],
				'pct'      => round(($c['used'] / 256) * 100, 1),
			);
			$current = gmp_add($current, $step);
		}

		$result['summary_24'] = $summary;
	} else {
		/* Return all addresses for the entire subnet */
		$result['addresses'] = cereus_ipam_visual_build_address_list($subnet_id, $subnet);
	}

	print json_encode($result, JSON_HEX_TAG | JSON_HEX_AMP);
	exit;
}

/* ========== AJAX: Visual map data (single /24 chunk) ========== */

function cereus_ipam_address_visual_data_chunk() {
	$subnet_id = (int) get_nfilter_request_var('subnet_id');
	$block = trim(get_nfilter_request_var('block'));

	header('Content-Type: application/json');

	if (!$subnet_id || !filter_var($block, FILTER_VALIDATE_IP)) {
		print json_encode(array('error' => 'Invalid parameters'));
		exit;
	}

	$subnet = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
	if (!cacti_sizeof($subnet)) {
		print json_encode(array('error' => 'Subnet not found'));
		exit;
	}

	/* Build full /24 IP list for this block */
	$octets = explode('.', $block);
	$base = $octets[0] . '.' . $octets[1] . '.' . $octets[2];

	$addresses_raw = db_fetch_assoc_prepared(
		"SELECT ip, hostname, mac_address, owner, state, id
		 FROM plugin_cereus_ipam_addresses
		 WHERE subnet_id = ? AND ip LIKE ?",
		array($subnet_id, $base . '.%')
	);

	$addr_map = array();
	if (cacti_sizeof($addresses_raw)) {
		foreach ($addresses_raw as $a) {
			$addr_map[$a['ip']] = $a;
		}
	}

	/* Check for conflicts in this block */
	$conflicts = array();
	$conflict_rows = db_fetch_assoc_prepared(
		"SELECT ip FROM plugin_cereus_ipam_scan_results
		 WHERE subnet_id = ? AND ip LIKE ? AND is_alive = 1
		 AND ip NOT IN (SELECT ip FROM plugin_cereus_ipam_addresses WHERE subnet_id = ? AND state != 'available')",
		array($subnet_id, $base . '.%', $subnet_id)
	);
	if (cacti_sizeof($conflict_rows)) {
		foreach ($conflict_rows as $cr) {
			$conflicts[$cr['ip']] = true;
		}
	}

	$list = array();
	for ($i = 0; $i < 256; $i++) {
		$ip = $base . '.' . $i;
		if (isset($addr_map[$ip])) {
			$a = $addr_map[$ip];
			$state = isset($conflicts[$ip]) ? 'conflict' : $a['state'];
			$list[] = array(
				'ip'       => $ip,
				'state'    => $state,
				'hostname' => $a['hostname'] ?? '',
				'mac'      => $a['mac_address'] ?? '',
				'owner'    => $a['owner'] ?? '',
				'id'       => (int) $a['id'],
			);
		} else {
			$state = isset($conflicts[$ip]) ? 'conflict' : 'available';
			$list[] = array(
				'ip'    => $ip,
				'state' => $state,
				'hostname' => '',
				'mac'   => '',
				'owner' => '',
				'id'    => 0,
			);
		}
	}

	print json_encode(array('addresses' => $list, 'block' => $block), JSON_HEX_TAG | JSON_HEX_AMP);
	exit;
}

/**
 * Build full address list JSON for a subnet.
 * Used by visual_data endpoint for /22 and smaller subnets.
 */
function cereus_ipam_visual_build_address_list($subnet_id, $subnet) {
	$mask = (int) $subnet['mask'];
	$range = cereus_ipam_cidr_to_range($subnet['subnet'], $mask);
	$start = cereus_ipam_ip_to_gmp($range['first']);
	$end   = cereus_ipam_ip_to_gmp($range['last']);

	$addresses_raw = db_fetch_assoc_prepared(
		"SELECT ip, hostname, mac_address, owner, state, id
		 FROM plugin_cereus_ipam_addresses WHERE subnet_id = ?",
		array($subnet_id)
	);

	$addr_map = array();
	if (cacti_sizeof($addresses_raw)) {
		foreach ($addresses_raw as $a) {
			$addr_map[$a['ip']] = $a;
		}
	}

	$list = array();
	$current = $start;
	while (gmp_cmp($current, $end) <= 0) {
		$ip = cereus_ipam_gmp_to_ip($current, 4);
		if (isset($addr_map[$ip])) {
			$a = $addr_map[$ip];
			$list[] = array(
				'ip'       => $ip,
				'state'    => $a['state'],
				'hostname' => $a['hostname'] ?? '',
				'mac'      => $a['mac_address'] ?? '',
				'owner'    => $a['owner'] ?? '',
				'id'       => (int) $a['id'],
			);
		} else {
			$list[] = array(
				'ip'    => $ip,
				'state' => 'available',
				'hostname' => '',
				'mac'   => '',
				'owner' => '',
				'id'    => 0,
			);
		}
		$current = gmp_add($current, 1);
	}

	return $list;
}

/* ==================== Inline Ping Check (AJAX) ==================== */

function cereus_ipam_address_ping_ajax() {
	include_once('./plugins/cereus_ipam/lib/scanner.php');

	$ip = trim(get_nfilter_request_var('ip', ''));

	header('Content-Type: application/json');

	if (!cereus_ipam_validate_ip($ip)) {
		print json_encode(array('status' => 'error', 'message' => 'Invalid IP address'));
		exit;
	}

	/* Use multi-method probe: TCP connect first, then ICMP fallback.
	 * TCP connect works under SELinux httpd_t context where ICMP is blocked. */
	$result = cereus_ipam_ping_host($ip, 1, true);

	print json_encode(array(
		'status'  => 'ok',
		'ip'      => $ip,
		'alive'   => $result['alive'],
		'latency' => $result['latency'],
		'method'  => $result['method'] ?? '',
	));
	exit;
}
