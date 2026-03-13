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
 | Cereus IPAM - Sections & Subnets Management UI                          |
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
include_once('./plugins/cereus_ipam/lib/threshold.php');
include_once('./plugins/cereus_ipam/lib/forecast.php');

$subnet_actions = array(
	1 => __('Delete', 'cereus_ipam'),
);

$section_actions = array(
	1 => __('Delete', 'cereus_ipam'),
);

$action = get_nfilter_request_var('action', '');

switch ($action) {
	case 'save':
		$save_component = get_nfilter_request_var('save_component', '');
		if ($save_component === 'section') {
			cereus_ipam_section_save();
		} elseif ($save_component === 'subnet') {
			cereus_ipam_subnet_save();
		}
		break;
	case 'actions':
		cereus_ipam_subnet_actions();
		break;
	case 'section_actions':
		cereus_ipam_section_actions();
		break;
	case 'edit':
		top_header();
		cereus_ipam_subnet_edit();
		bottom_footer();
		break;
	case 'section_edit':
		top_header();
		cereus_ipam_section_edit();
		bottom_footer();
		break;
	default:
		top_header();
		cereus_ipam_list();
		bottom_footer();
		break;
}

/* ==================== Section Save ==================== */

function cereus_ipam_section_save() {
	$id        = get_filter_request_var('id');
	$name      = cereus_ipam_sanitize_text(get_nfilter_request_var('name', ''), 255);
	$desc      = cereus_ipam_sanitize_text(get_nfilter_request_var('description', ''), 65535);
	$parent_id = get_filter_request_var('parent_id', FILTER_VALIDATE_INT);
	$order     = get_filter_request_var('display_order', FILTER_VALIDATE_INT);

	/* Tenant assignment (Enterprise) */
	$tenant_id = null;
	if (cereus_ipam_license_has_multitenancy()) {
		$tenant_id = get_filter_request_var('tenant_id', FILTER_VALIDATE_INT);
		if ($tenant_id === false || $tenant_id < 0) {
			$tenant_id = null;
		}
		if ($tenant_id === 0) {
			$tenant_id = null;
		}
	}

	if ($parent_id === false || $parent_id < 0) {
		$parent_id = 0;
	}
	if ($order === false) {
		$order = 0;
	}

	/* Helper to preserve form data on validation failure */
	$form_data_section = array(
		'name' => $name, 'description' => $desc,
		'parent_id' => $parent_id, 'display_order' => $order,
		'tenant_id' => $tenant_id,
	);

	if (empty($name)) {
		$_SESSION['cipam_form_section'] = $form_data_section;
		raise_message('cereus_ipam_name', __('Section name is required.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam.php?action=section_edit&id=' . $id);
		exit;
	}

	if ($id > 0) {
		$old = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_sections WHERE id = ?", array($id));
		db_execute_prepared("UPDATE plugin_cereus_ipam_sections SET
			name = ?, description = ?, parent_id = ?, display_order = ?, tenant_id = ?
			WHERE id = ?",
			array($name, $desc, $parent_id, $order, $tenant_id, $id));
		cereus_ipam_changelog_record('update', 'section', $id, $old, array('name' => $name, 'description' => $desc, 'parent_id' => $parent_id, 'tenant_id' => $tenant_id));
		$new_id = $id;
	} else {
		db_execute_prepared("INSERT INTO plugin_cereus_ipam_sections
			(name, description, parent_id, display_order, tenant_id)
			VALUES (?, ?, ?, ?, ?)",
			array($name, $desc, $parent_id, $order, $tenant_id));
		$new_id = db_fetch_insert_id();
		cereus_ipam_changelog_record('create', 'section', $new_id, null, array('name' => $name, 'tenant_id' => $tenant_id));
	}

	/* Save RBAC permissions */
	if (cereus_ipam_license_has_rbac()) {
		$save_id = ($id > 0) ? $id : $new_id;
		if ($save_id > 0) {
			cereus_ipam_save_section_permissions($save_id);
		}
	}

	raise_message('cereus_ipam_saved', __('Section saved.', 'cereus_ipam'), MESSAGE_LEVEL_INFO);
	header('Location: cereus_ipam.php');
	exit;
}

/* ==================== Subnet Save ==================== */

function cereus_ipam_subnet_save() {
	$id         = get_filter_request_var('id');
	$section_id = get_filter_request_var('section_id', FILTER_VALIDATE_INT);
	$subnet     = trim(get_nfilter_request_var('subnet', ''));
	$mask       = get_filter_request_var('mask', FILTER_VALIDATE_INT);
	$desc       = cereus_ipam_sanitize_text(get_nfilter_request_var('description', ''), 255);
	$gateway    = trim(get_nfilter_request_var('gateway', ''));
	$nameservers = cereus_ipam_sanitize_text(get_nfilter_request_var('nameservers', ''), 512);
	$threshold  = get_filter_request_var('threshold_pct', FILTER_VALIDATE_INT);
	$vlan_id    = get_filter_request_var('vlan_id', FILTER_VALIDATE_INT);
	$vrf_id     = get_filter_request_var('vrf_id', FILTER_VALIDATE_INT);

	/* Scan scheduling (Professional+) */
	$scan_enabled  = 0;
	$scan_interval = 3600;
	if (cereus_ipam_license_has_scanning()) {
		$scan_enabled  = isset_request_var('scan_enabled') ? 1 : 0;
		$scan_interval = get_filter_request_var('scan_interval', FILTER_VALIDATE_INT);
		if ($scan_interval === false || $scan_interval < 60) {
			$scan_interval = 3600;
		}
	}

	if ($threshold === false || $threshold < 0 || $threshold > 100) {
		$threshold = 90;
	}
	if (!$vlan_id || !cereus_ipam_license_has_vlans()) {
		$vlan_id = null;
	}
	if (!$vrf_id || !cereus_ipam_license_has_vrfs()) {
		$vrf_id = null;
	}

	/* License limit check */
	$max = cereus_ipam_license_max_subnets();
	if ($max > 0 && $id == 0) {
		$current = cereus_ipam_license_subnet_count();
		if ($current >= $max) {
			raise_message('cereus_ipam_limit', __('Subnet limit reached for your license tier (%d). Please upgrade.', $max, 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
			header('Location: cereus_ipam.php');
			exit;
		}
	}

	/* Helper to preserve form data on validation failure */
	$form_data_subnet = array(
		'section_id' => $section_id, 'subnet' => $subnet, 'mask' => $mask,
		'description' => $desc, 'gateway' => $gateway, 'nameservers' => $nameservers,
		'threshold_pct' => $threshold, 'vlan_id' => $vlan_id, 'vrf_id' => $vrf_id,
		'scan_enabled' => $scan_enabled, 'scan_interval' => $scan_interval,
	);

	/* Validate */
	if (!cereus_ipam_validate_ip($subnet)) {
		$_SESSION['cipam_form_subnet'] = $form_data_subnet;
		raise_message('cereus_ipam_ip', __('Invalid subnet address.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam.php?action=edit&id=' . $id);
		exit;
	}

	$version = cereus_ipam_ip_version($subnet);

	/* IPv6 check */
	if ($version == 6 && !cereus_ipam_license_has_ipv6()) {
		$_SESSION['cipam_form_subnet'] = $form_data_subnet;
		raise_message('cereus_ipam_ipv6', __('IPv6 requires a Professional license.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam.php?action=edit&id=' . $id);
		exit;
	}

	if (!cereus_ipam_validate_cidr($mask, $version)) {
		$_SESSION['cipam_form_subnet'] = $form_data_subnet;
		raise_message('cereus_ipam_cidr', __('Invalid CIDR mask.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam.php?action=edit&id=' . $id);
		exit;
	}

	/* Ensure proper network address */
	$network = cereus_ipam_network_address($subnet, $mask);
	$subnet = $network;

	/* Validate gateway if provided */
	if (!empty($gateway) && !cereus_ipam_validate_ip($gateway)) {
		$_SESSION['cipam_form_subnet'] = $form_data_subnet;
		raise_message('cereus_ipam_gw', __('Invalid gateway address.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam.php?action=edit&id=' . $id);
		exit;
	}

	/* Auto-detect parent subnet if not explicitly set */
	$parent_id = get_filter_request_var('parent_id', FILTER_VALIDATE_INT);
	if ($parent_id === false || $parent_id < 0) {
		$parent_id = 0;
	}

	/* If parent_id not manually set, auto-detect the smallest containing subnet */
	if ($parent_id == 0 && cereus_ipam_license_at_least('professional')) {
		$parent_id = cereus_ipam_find_parent_subnet($subnet, $mask, $section_id, $id);
	}

	if ($id > 0) {
		$old = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_subnets WHERE id = ?", array($id));
		db_execute_prepared("UPDATE plugin_cereus_ipam_subnets SET
			section_id = ?, parent_id = ?, subnet = ?, mask = ?, description = ?,
			gateway = ?, nameservers = ?, threshold_pct = ?,
			vlan_id = ?, vrf_id = ?, scan_enabled = ?, scan_interval = ?
			WHERE id = ?",
			array($section_id, $parent_id, $subnet, $mask, $desc, $gateway, $nameservers, $threshold, $vlan_id, $vrf_id, $scan_enabled, $scan_interval, $id));
		cereus_ipam_changelog_record('update', 'subnet', $id, $old, array('subnet' => $subnet, 'mask' => $mask));
		$new_id = $id;

		/* Re-parent any child subnets that fit inside this one */
		cereus_ipam_reparent_children($new_id, $subnet, $mask, $section_id);
	} else {
		db_execute_prepared("INSERT INTO plugin_cereus_ipam_subnets
			(section_id, parent_id, subnet, mask, description, gateway, nameservers, threshold_pct, vlan_id, vrf_id, scan_enabled, scan_interval)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			array($section_id, $parent_id, $subnet, $mask, $desc, $gateway, $nameservers, $threshold, $vlan_id, $vrf_id, $scan_enabled, $scan_interval));
		$new_id = db_fetch_insert_id();
		cereus_ipam_changelog_record('create', 'subnet', $new_id, null, array('subnet' => "$subnet/$mask"));

		/* Re-parent any child subnets that fit inside this one */
		cereus_ipam_reparent_children($new_id, $subnet, $mask, $section_id);
	}

	/* Save custom fields */
	if (cereus_ipam_license_has_custom_fields()) {
		$cf_json = cereus_ipam_save_custom_fields('subnet');
		if ($new_id > 0) {
			db_execute_prepared("UPDATE plugin_cereus_ipam_subnets SET custom_fields = ? WHERE id = ?",
				array($cf_json, $new_id));
		}
	}

	/* Save tag assignments */
	if ($new_id > 0) {
		$tag_ids = array();
		if (isset($_POST['tag_ids']) && is_array($_POST['tag_ids'])) {
			$tag_ids = $_POST['tag_ids'];
		}
		cereus_ipam_save_object_tags('subnet', $new_id, $tag_ids);
	}

	raise_message('cereus_ipam_saved', __('Subnet saved.', 'cereus_ipam'), MESSAGE_LEVEL_INFO);
	header('Location: cereus_ipam.php?action=edit&id=' . $new_id);
	exit;
}

/* ==================== Subnet Bulk Actions ==================== */

function cereus_ipam_subnet_actions() {
	global $subnet_actions;

	if (isset_request_var('selected_items')) {
		$selected_items = sanitize_unserialize_selected_items(get_nfilter_request_var('selected_items'));

		if ($selected_items !== false) {
			$drp_action = get_nfilter_request_var('drp_action');

			foreach ($selected_items as $id) {
				if (!is_numeric($id) || $id <= 0) continue;

				switch ($drp_action) {
					case '1': /* delete */
						$old = db_fetch_row_prepared("SELECT subnet, mask FROM plugin_cereus_ipam_subnets WHERE id = ?", array($id));
						db_execute_prepared("DELETE FROM plugin_cereus_ipam_addresses WHERE subnet_id = ?", array($id));
						db_execute_prepared("DELETE FROM plugin_cereus_ipam_scan_results WHERE subnet_id = ?", array($id));
						db_execute_prepared("DELETE FROM plugin_cereus_ipam_conflicts WHERE subnet_id = ?", array($id));
						db_execute_prepared("DELETE FROM plugin_cereus_ipam_tag_assignments WHERE object_type = 'subnet' AND object_id = ?", array($id));
						db_execute_prepared("DELETE FROM plugin_cereus_ipam_subnets WHERE id = ?", array($id));
						if (cacti_sizeof($old)) {
							cereus_ipam_changelog_record('delete', 'subnet', $id, $old, null);
						}
						break;
				}
			}
		}

		header('Location: cereus_ipam.php');
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
	form_start('cereus_ipam.php');
	html_start_box($subnet_actions[get_nfilter_request_var('drp_action')], '60%', '', '3', 'center', '');

	$total_affected_addrs = 0;
	$total_affected_scans = 0;

	if (cacti_sizeof($item_array)) {
		foreach ($item_array as $id) {
			$row = db_fetch_row_prepared('SELECT subnet, mask, description FROM plugin_cereus_ipam_subnets WHERE id = ?', array($id));
			if (cacti_sizeof($row)) {
				$addr_count = (int) db_fetch_cell_prepared('SELECT COUNT(*) FROM plugin_cereus_ipam_addresses WHERE subnet_id = ?', array($id));
				$scan_count = (int) db_fetch_cell_prepared('SELECT COUNT(*) FROM plugin_cereus_ipam_scan_results WHERE subnet_id = ?', array($id));
				$total_affected_addrs += $addr_count;
				$total_affected_scans += $scan_count;

				$impact = '';
				if ($addr_count > 0) {
					$impact = ' <span style="color:#e74c3c;">(' . $addr_count . ' ' . __('addresses', 'cereus_ipam') . ')</span>';
				}
				print '<tr><td class="odd"><span class="deleteMarker">' . html_escape($row['subnet'] . '/' . $row['mask']) . ' - ' . html_escape($row['description']) . '</span>' . $impact . '</td></tr>';
			}
		}
	}

	$warning = __('Are you sure you want to delete the selected subnet(s) and all their addresses?', 'cereus_ipam');
	if ($total_affected_addrs > 0) {
		$warning .= '<br><br><strong style="color:#e74c3c;">' . __('This will permanently delete %s address record(s) and %s scan result(s).', $total_affected_addrs, $total_affected_scans, 'cereus_ipam') . '</strong>';
	}
	print '<tr><td class="saveRow"><p>' . $warning . '</p></td></tr>';

	$save_html = "<input type='button' class='ui-button ui-corner-all ui-widget' value='" . __esc('Cancel', 'cereus_ipam') . "' onClick='cactiReturnTo(\"cereus_ipam.php\")'>&nbsp;";
	$save_html .= "<input type='submit' class='ui-button ui-corner-all ui-widget' value='" . __esc('Continue', 'cereus_ipam') . "'>";
	print "<tr><td class='saveRow'>$save_html</td></tr>";

	html_end_box();
	form_hidden_box('action', 'actions', '');
	form_hidden_box('selected_items', serialize($item_array), '');
	form_hidden_box('drp_action', get_nfilter_request_var('drp_action'), '');
	form_end();
	bottom_footer();
}

/* ==================== Section Bulk Actions ==================== */

function cereus_ipam_section_actions() {
	global $section_actions;

	if (isset_request_var('selected_items')) {
		$selected_items = sanitize_unserialize_selected_items(get_nfilter_request_var('selected_items'));

		if ($selected_items !== false) {
			$drp_action = get_nfilter_request_var('drp_action');

			foreach ($selected_items as $id) {
				if (!is_numeric($id) || $id <= 0) continue;

				switch ($drp_action) {
					case '1':
						/* Delete section and all its subnets and addresses */
						$subnets = db_fetch_assoc_prepared("SELECT id FROM plugin_cereus_ipam_subnets WHERE section_id = ?", array($id));
						if (cacti_sizeof($subnets)) foreach ($subnets as $s) {
							db_execute_prepared("DELETE FROM plugin_cereus_ipam_addresses WHERE subnet_id = ?", array($s['id']));
							db_execute_prepared("DELETE FROM plugin_cereus_ipam_scan_results WHERE subnet_id = ?", array($s['id']));
							db_execute_prepared("DELETE FROM plugin_cereus_ipam_conflicts WHERE subnet_id = ?", array($s['id']));
						}
						db_execute_prepared("DELETE FROM plugin_cereus_ipam_subnets WHERE section_id = ?", array($id));
						db_execute_prepared("DELETE FROM plugin_cereus_ipam_sections WHERE id = ?", array($id));
						cereus_ipam_changelog_record('delete', 'section', $id, null, null);
						break;
				}
			}
		}

		header('Location: cereus_ipam.php');
		exit;
	}
}

/* ==================== Section Edit ==================== */

function cereus_ipam_section_edit() {
	$id = get_filter_request_var('id');

	if ($id > 0) {
		$section = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_sections WHERE id = ?", array($id));
		if (!cacti_sizeof($section)) {
			raise_message('cereus_ipam_nf', __('Section not found.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
			header('Location: cereus_ipam.php');
			exit;
		}
		$header = __('Edit Section: %s', html_escape($section['name']), 'cereus_ipam');
	} else {
		$section = array();
		$header = __('New Section', 'cereus_ipam');
	}

	/* Restore form data from session after validation error */
	if (isset($_SESSION['cipam_form_section']) && is_array($_SESSION['cipam_form_section'])) {
		$section = array_merge($section, $_SESSION['cipam_form_section']);
		unset($_SESSION['cipam_form_section']);
	}

	$parent_dropdown = cereus_ipam_get_sections_dropdown();
	/* Remove self and children from parent dropdown to prevent loops */
	if ($id > 0) {
		unset($parent_dropdown[$id]);
	}

	$fields = array(
		'section_header' => array(
			'friendly_name' => __('Section Settings', 'cereus_ipam'),
			'method'        => 'spacer',
		),
		'name' => array(
			'friendly_name' => __('Name', 'cereus_ipam'),
			'description'   => __('A descriptive name for this section.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $section['name'] ?? '',
			'max_length'    => 255,
			'size'          => 60,
		),
		'description' => array(
			'friendly_name' => __('Description', 'cereus_ipam'),
			'description'   => __('Optional description.', 'cereus_ipam'),
			'method'        => 'textarea',
			'value'         => $section['description'] ?? '',
			'textarea_rows' => 3,
			'textarea_cols' => 60,
			'max_length'    => 65535,
		),
		'parent_id' => array(
			'friendly_name' => __('Parent Section', 'cereus_ipam'),
			'description'   => __('Select a parent section for hierarchical grouping.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'value'         => $section['parent_id'] ?? 0,
			'array'         => $parent_dropdown,
		),
		'display_order' => array(
			'friendly_name' => __('Display Order', 'cereus_ipam'),
			'description'   => __('Order for sorting sections.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $section['display_order'] ?? 0,
			'max_length'    => 5,
			'size'          => 5,
		),
	);

	/* Tenant assignment (Enterprise) */
	if (cereus_ipam_license_has_multitenancy()) {
		$tenants = db_fetch_assoc("SELECT id, name FROM plugin_cereus_ipam_tenants WHERE enabled = 1 ORDER BY name");
		$tenant_dropdown = array(0 => __('None (Global)', 'cereus_ipam'));
		foreach ($tenants as $t) {
			$tenant_dropdown[$t['id']] = $t['name'];
		}
		$fields['tenant_id'] = array(
			'friendly_name' => __('Tenant', 'cereus_ipam'),
			'description'   => __('Assign this section to a tenant for isolated views.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'value'         => $section['tenant_id'] ?? 0,
			'array'         => $tenant_dropdown,
		);
	}

	form_start('cereus_ipam.php');
	html_start_box($header, '100%', '', '3', 'center', '');
	draw_edit_form(array(
		'config' => array('no_form_tag' => true),
		'fields' => $fields,
	));
	html_end_box();

	/* RBAC permissions editor (Professional+) */
	if (cereus_ipam_license_has_rbac() && $id > 0) {
		cereus_ipam_render_permissions_editor($id);
	}

	form_hidden_box('id', $id, '0');
	form_hidden_box('save_component', 'section', '');
	form_save_button('cereus_ipam.php', 'return');
}

/* ==================== Subnet Edit ==================== */

function cereus_ipam_subnet_edit() {
	$id = get_filter_request_var('id');

	if ($id > 0) {
		$subnet = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_subnets WHERE id = ?", array($id));
		if (!cacti_sizeof($subnet)) {
			raise_message('cereus_ipam_nf', __('Subnet not found.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
			header('Location: cereus_ipam.php');
			exit;
		}
		$header = __('Edit Subnet: %s/%s', html_escape($subnet['subnet']), $subnet['mask'], 'cereus_ipam');
	} else {
		$subnet = array();
		$section_id = get_filter_request_var('section_id', FILTER_VALIDATE_INT);
		if ($section_id) {
			$subnet['section_id'] = $section_id;
		}
		$header = __('New Subnet', 'cereus_ipam');
	}

	/* Restore form data from session after validation error */
	if (isset($_SESSION['cipam_form_subnet']) && is_array($_SESSION['cipam_form_subnet'])) {
		$subnet = array_merge($subnet, $_SESSION['cipam_form_subnet']);
		unset($_SESSION['cipam_form_subnet']);
	}

	$sections_dropdown = cereus_ipam_get_sections_dropdown();
	unset($sections_dropdown[0]); /* Remove "None (Top Level)" - subnets must have a section */
	if (!cacti_sizeof($sections_dropdown)) {
		$sections_dropdown = array(0 => __('-- Create a section first --', 'cereus_ipam'));
	}

	/* Build mask dropdown */
	$mask_array = array();
	for ($i = 8; $i <= 32; $i++) {
		$dotted = cereus_ipam_cidr_to_dotted($i);
		$hosts = cereus_ipam_usable_hosts($i, 4);
		$mask_array[$i] = '/' . $i . ' (' . $dotted . ') - ' . $hosts . ' ' . __('hosts', 'cereus_ipam');
	}

	$fields = array(
		'general_header' => array(
			'friendly_name' => __('Subnet Settings', 'cereus_ipam'),
			'method'        => 'spacer',
		),
		'section_id' => array(
			'friendly_name' => __('Section', 'cereus_ipam'),
			'description'   => __('Section this subnet belongs to.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'value'         => $subnet['section_id'] ?? '',
			'array'         => $sections_dropdown,
		),
		'subnet' => array(
			'friendly_name' => __('Subnet Address', 'cereus_ipam'),
			'description'   => __('Network address (e.g., 192.168.1.0 or 2001:db8::).', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $subnet['subnet'] ?? '',
			'max_length'    => 45,
			'size'          => 40,
		),
		'mask' => array(
			'friendly_name' => __('CIDR Mask', 'cereus_ipam'),
			'description'   => __('Subnet prefix length.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'value'         => $subnet['mask'] ?? 24,
			'array'         => $mask_array,
		),
		'description' => array(
			'friendly_name' => __('Description', 'cereus_ipam'),
			'description'   => __('Short description of the subnet purpose.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $subnet['description'] ?? '',
			'max_length'    => 255,
			'size'          => 60,
		),
		'gateway' => array(
			'friendly_name' => __('Gateway', 'cereus_ipam'),
			'description'   => __('Default gateway IP address.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $subnet['gateway'] ?? '',
			'max_length'    => 45,
			'size'          => 40,
		),
		'nameservers' => array(
			'friendly_name' => __('Nameservers', 'cereus_ipam'),
			'description'   => __('Comma-separated list of DNS servers.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $subnet['nameservers'] ?? '',
			'max_length'    => 512,
			'size'          => 60,
		),
		'threshold_pct' => array(
			'friendly_name' => __('Alert Threshold (%)', 'cereus_ipam'),
			'description'   => __('Send alert when utilization exceeds this percentage.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $subnet['threshold_pct'] ?? 90,
			'max_length'    => 3,
			'size'          => 5,
		),
	);

	/* Parent subnet dropdown (Professional+ for hierarchy) */
	if (cereus_ipam_license_at_least('professional')) {
		$current_mask = $subnet['mask'] ?? 128;
		$parent_dropdown = cereus_ipam_get_parent_subnets_dropdown(
			$subnet['section_id'] ?? 0,
			$current_mask,
			$id
		);
		$fields['parent_id'] = array(
			'friendly_name' => __('Parent Subnet', 'cereus_ipam'),
			'description'   => __('Nest this subnet under a larger parent subnet. Auto-detected if left as None.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'value'         => $subnet['parent_id'] ?? 0,
			'array'         => $parent_dropdown,
		);
	}

	/* Add VLAN/VRF fields if licensed */
	if (cereus_ipam_license_has_vlans()) {
		$fields['vlan_id'] = array(
			'friendly_name' => __('VLAN', 'cereus_ipam'),
			'description'   => __('Associated VLAN.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'value'         => $subnet['vlan_id'] ?? '',
			'array'         => cereus_ipam_get_vlans_dropdown(),
		);
	}

	if (cereus_ipam_license_has_vrfs()) {
		$fields['vrf_id'] = array(
			'friendly_name' => __('VRF', 'cereus_ipam'),
			'description'   => __('Virtual Routing and Forwarding instance.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'value'         => $subnet['vrf_id'] ?? '',
			'array'         => cereus_ipam_get_vrfs_dropdown(),
		);
	}

	/* Scan scheduling (Professional+) */
	if (cereus_ipam_license_has_scanning()) {
		$scan_intervals = array(
			300    => __('Every 5 minutes', 'cereus_ipam'),
			600    => __('Every 10 minutes', 'cereus_ipam'),
			900    => __('Every 15 minutes', 'cereus_ipam'),
			1800   => __('Every 30 minutes', 'cereus_ipam'),
			3600   => __('Every 1 hour', 'cereus_ipam'),
			7200   => __('Every 2 hours', 'cereus_ipam'),
			14400  => __('Every 4 hours', 'cereus_ipam'),
			28800  => __('Every 8 hours', 'cereus_ipam'),
			43200  => __('Every 12 hours', 'cereus_ipam'),
			86400  => __('Every 24 hours', 'cereus_ipam'),
			604800 => __('Every 7 days', 'cereus_ipam'),
		);

		$fields['scan_spacer'] = array(
			'friendly_name' => __('Scan Schedule (Professional+)', 'cereus_ipam'),
			'method'        => 'spacer',
		);
		$fields['scan_enabled'] = array(
			'friendly_name' => __('Enable Scheduled Scanning', 'cereus_ipam'),
			'description'   => __('Automatically scan this subnet on a recurring schedule via the Cacti poller.', 'cereus_ipam'),
			'method'        => 'checkbox',
			'value'         => $subnet['scan_enabled'] ?? '',
		);
		$fields['scan_interval'] = array(
			'friendly_name' => __('Scan Interval', 'cereus_ipam'),
			'description'   => __('How often to scan this subnet. The scan runs during the Cacti poller cycle following the interval.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'value'         => $subnet['scan_interval'] ?? 3600,
			'array'         => $scan_intervals,
		);
	}

	/* Custom fields (Professional+) */
	if (cereus_ipam_license_has_custom_fields()) {
		$cf_values = json_decode($subnet['custom_fields'] ?? '{}', true);
		if (!is_array($cf_values)) $cf_values = array();
		$cf_fields = cereus_ipam_render_custom_fields('subnet', $cf_values);
		if (cacti_sizeof($cf_fields)) {
			$fields['cf_spacer'] = array(
				'friendly_name' => __('Custom Fields', 'cereus_ipam'),
				'method' => 'spacer',
			);
			$fields = array_merge($fields, $cf_fields);
		}
	}

	form_start('cereus_ipam.php');
	html_start_box($header, '100%', '', '3', 'center', '');
	draw_edit_form(array(
		'config' => array('no_form_tag' => true),
		'fields' => $fields,
	));
	html_end_box();

	/* Tags selector */
	$all_tags = cereus_ipam_get_all_tags();
	if (cacti_sizeof($all_tags)) {
		$assigned_tag_ids = array();
		if ($id > 0) {
			$assigned = cereus_ipam_get_object_tags('subnet', $id);
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

	/* Show utilization and address summary for existing subnets */
	if ($id > 0) {
		$util = cereus_ipam_subnet_utilization($id);
		$range = cereus_ipam_cidr_to_range($subnet['subnet'], $subnet['mask']);

		html_start_box(__('Subnet Information', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr class="even"><td style="padding:8px 15px;">';
		print '<table class="filterTable">';
		print '<tr><td><b>' . __('Range:', 'cereus_ipam') . '</b></td><td>' . html_escape($range['first']) . ' - ' . html_escape($range['last']) . '</td></tr>';
		print '<tr><td><b>' . __('Total Hosts:', 'cereus_ipam') . '</b></td><td>' . number_format_i18n($util['total']) . '</td></tr>';
		print '<tr><td><b>' . __('Used:', 'cereus_ipam') . '</b></td><td>' . number_format_i18n($util['used']) . '</td></tr>';
		print '<tr><td><b>' . __('Free:', 'cereus_ipam') . '</b></td><td>' . number_format_i18n($util['free']) . '</td></tr>';
		print '<tr><td><b>' . __('Utilization:', 'cereus_ipam') . '</b></td><td>' . cereus_ipam_utilization_bar($util['pct']) . '</td></tr>';
		if (!empty($subnet['last_scanned'])) {
			print '<tr><td><b>' . __('Last Scanned:', 'cereus_ipam') . '</b></td><td>' . html_escape($subnet['last_scanned']) . '</td></tr>';
		}
		if (!empty($subnet['scan_enabled'])) {
			$interval_secs = (int) ($subnet['scan_interval'] ?? 3600);
			if ($interval_secs >= 86400) {
				$interval_label = round($interval_secs / 86400) . ' ' . __('day(s)', 'cereus_ipam');
			} elseif ($interval_secs >= 3600) {
				$interval_label = round($interval_secs / 3600) . ' ' . __('hour(s)', 'cereus_ipam');
			} else {
				$interval_label = round($interval_secs / 60) . ' ' . __('minute(s)', 'cereus_ipam');
			}
			print '<tr><td><b>' . __('Scan Schedule:', 'cereus_ipam') . '</b></td><td><span style="color:#27ae60;">&#10003; ' . __('Every %s', $interval_label, 'cereus_ipam') . '</span></td></tr>';

			if (!empty($subnet['last_scanned'])) {
				$next_scan = strtotime($subnet['last_scanned']) + $interval_secs;
				$next_label = ($next_scan <= time())
					? __('Due now (next poller cycle)', 'cereus_ipam')
					: date('Y-m-d H:i:s', $next_scan);
				print '<tr><td><b>' . __('Next Scan:', 'cereus_ipam') . '</b></td><td>' . html_escape($next_label) . '</td></tr>';
			}
		}
		print '</table>';
		print '</td></tr>';
		html_end_box();

		/* Quick links */
		html_start_box(__('Actions', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr class="even"><td style="padding:8px 15px;">';
		print '<a class="linkEditMain" href="cereus_ipam_addresses.php?subnet_id=' . $id . '">' . __('View/Manage IP Addresses', 'cereus_ipam') . '</a>';
		print ' | <a class="linkEditMain" href="cereus_ipam_import.php?subnet_id=' . $id . '">' . __('Import CSV', 'cereus_ipam') . '</a>';
		print ' | <a class="linkEditMain" href="cereus_ipam_addresses.php?action=export&subnet_id=' . $id . '">' . __('Export CSV', 'cereus_ipam') . '</a>';
		if (cereus_ipam_license_has_scanning()) {
			print ' | <a class="linkEditMain" href="cereus_ipam_scan.php?subnet_id=' . $id . '">' . __('Scan Subnet', 'cereus_ipam') . '</a>';
		}
		print '</td></tr>';
		html_end_box();
	}

	form_hidden_box('id', $id, '0');
	form_hidden_box('save_component', 'subnet', '');
	form_save_button('cereus_ipam.php', 'return');
}

/* ==================== Main List View ==================== */

function cereus_ipam_list() {
	global $subnet_actions;

	/* Filter handling */
	if (isset_request_var('clear')) {
		kill_session_var('sess_cipam_filter');
		kill_session_var('sess_cipam_section');
		kill_session_var('sess_cipam_vlan');
		kill_session_var('sess_cipam_vrf');
		kill_session_var('sess_cipam_tenant');
		kill_session_var('sess_cipam_tag');
		kill_session_var('sess_cipam_rows');
		kill_session_var('sess_cipam_page');
		unset_request_var('filter');
		unset_request_var('section_id');
		unset_request_var('vlan_id');
		unset_request_var('vrf_id');
		unset_request_var('tenant_id');
		unset_request_var('tag_id');
		unset_request_var('rows');
		unset_request_var('page');
	}

	load_current_session_value('filter',     'sess_cipam_filter',  '');
	load_current_session_value('section_id', 'sess_cipam_section', '-1');
	load_current_session_value('vlan_id',    'sess_cipam_vlan',    '-1');
	load_current_session_value('vrf_id',     'sess_cipam_vrf',     '-1');
	load_current_session_value('tenant_id',  'sess_cipam_tenant',  '-1');
	load_current_session_value('tag_id',     'sess_cipam_tag',     '-1');
	load_current_session_value('rows',       'sess_cipam_rows',    '-1');
	load_current_session_value('page',       'sess_cipam_page',    '1');

	$filter     = get_request_var('filter');
	$section_id = get_request_var('section_id');
	$vlan_id    = get_request_var('vlan_id');
	$vrf_id     = get_request_var('vrf_id');
	$tenant_id  = get_request_var('tenant_id');
	$tag_filt   = get_request_var('tag_id');
	$rows       = get_request_var('rows');
	$page       = get_request_var('page');

	if ($rows == -1) {
		$rows = read_config_option('num_rows_table');
	}

	$rows = max(1, (int) $rows);
	$page = max(1, (int) $page);

	/* License info */
	$tier  = cereus_ipam_license_tier();
	$max   = cereus_ipam_license_max_subnets();
	$count = cereus_ipam_license_subnet_count();
	$limit_text = ($max > 0) ? "$count / $max" : "$count / " . __('Unlimited', 'cereus_ipam');

	/* Sections list */
	$sections = cereus_ipam_get_sections_tree();

	/* Apply RBAC filtering */
	if (cereus_ipam_license_has_rbac()) {
		$sections = cereus_ipam_filter_sections_by_permission($sections, 'view');
	}

	/* Apply tenant filtering */
	if (cereus_ipam_license_has_multitenancy()) {
		$user_id = $_SESSION['sess_user_id'] ?? 0;
		$user_tenant = cereus_ipam_get_user_tenant($user_id);

		/* Cacti admin (user_id 1) can see all tenants */
		if ($user_tenant > 0 && (int)$user_id !== 1) {
			/* Force tenant filter to user's tenant */
			$tenant_id = $user_tenant;

			/* Filter sections to only show this tenant's sections + global sections */
			$sections = array_filter($sections, function($s) use ($user_tenant) {
				$tid = $s['tenant_id'] ?? 0;
				return $tid == 0 || $tid == $user_tenant;
			});
			$sections = array_values($sections);
		}
	}

	$section_dropdown = array('-1' => __('All Sections', 'cereus_ipam'));
	foreach ($sections as $s) {
		$prefix = str_repeat('-- ', $s['depth']);
		$section_dropdown[$s['id']] = $prefix . $s['name'];
	}

	/* ---- Sections Box ---- */
	html_start_box(
		__('Sections', 'cereus_ipam'),
		'100%', '', '3', 'center',
		'cereus_ipam.php?action=section_edit&id=0'
	);

	if (cacti_sizeof($sections)) {
		$display_text = array(
			array('display' => __('Name', 'cereus_ipam'), 'align' => 'left'),
			array('display' => __('Subnets', 'cereus_ipam'), 'align' => 'center'),
			array('display' => __('Description', 'cereus_ipam'), 'align' => 'left'),
		);
		html_header($display_text);

		foreach ($sections as $s) {
			$prefix = str_repeat('&mdash; ', $s['depth']);
			$subnet_count = db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_subnets WHERE section_id = ?", array($s['id']));

			form_alternate_row('section_' . $s['id']);
			form_selectable_cell(
				$prefix . '<a class="linkEditMain" href="cereus_ipam.php?action=section_edit&id=' . $s['id'] . '">' . html_escape($s['name']) . '</a>',
				$s['id']
			);
			form_selectable_cell($subnet_count, $s['id'], '', 'center');
			form_selectable_cell(html_escape($s['description'] ?? ''), $s['id']);
			form_end_row();
		}
	} else {
		print '<tr><td colspan="3"><em>' . __('No sections. Click the + to create one.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box();

	/* ---- Capacity Forecast Widget (Enterprise) ---- */
	if (cereus_ipam_license_at_least('enterprise')) {
		$forecasts = cereus_ipam_forecast_summary();
		if (cacti_sizeof($forecasts)) {
			$top5 = array_slice($forecasts, 0, 5);
			html_start_box(__('Capacity Forecast', 'cereus_ipam') . ' — ' . __('Subnets Approaching Exhaustion', 'cereus_ipam'), '100%', '', '3', 'center', '');
			$fc_cols = array(
				array('display' => __('Subnet', 'cereus_ipam'),          'align' => 'left'),
				array('display' => __('Description', 'cereus_ipam'),     'align' => 'left'),
				array('display' => __('Current', 'cereus_ipam'),         'align' => 'center'),
				array('display' => __('Growth/Day', 'cereus_ipam'),      'align' => 'center'),
				array('display' => __('Exhaustion Date', 'cereus_ipam'), 'align' => 'center'),
				array('display' => __('Days Left', 'cereus_ipam'),       'align' => 'center'),
			);
			html_header($fc_cols);

			foreach ($top5 as $fc) {
				$urgency_color = ($fc['days_remaining'] <= 30) ? '#e74c3c' : (($fc['days_remaining'] <= 90) ? '#f39c12' : '#27ae60');
				form_alternate_row();
				print '<td><a class="linkEditMain" href="cereus_ipam.php?action=edit&id=' . $fc['subnet_id'] . '">' . html_escape($fc['subnet']) . '</a></td>';
				print '<td>' . html_escape($fc['description'] ?? '') . '</td>';
				print '<td class="center">' . $fc['current_pct'] . '%</td>';
				print '<td class="center">+' . number_format($fc['daily_growth'], 2) . '%</td>';
				print '<td class="center">' . html_escape($fc['exhaustion_date']) . '</td>';
				print '<td class="center" style="color:' . $urgency_color . '; font-weight:bold;">' . $fc['days_remaining'] . ' ' . __('days', 'cereus_ipam') . '</td>';
				form_end_row();
			}

			html_end_box();
		}
	}

	/* ---- Subnets Filter ---- */
	html_start_box(
		__('Subnets', 'cereus_ipam') . ' [' . ucfirst($tier) . '] (' . $limit_text . ')',
		'100%', '', '3', 'center',
		'cereus_ipam.php?action=edit&id=0'
	);
	?>
	<tr class='even'>
		<td>
			<form id='form_cipam_filter' action='cereus_ipam.php'>
				<table class='filterTable'>
					<tr>
						<td><?php print __('Search', 'cereus_ipam'); ?></td>
						<td><input type='text' class='ui-state-default ui-corner-all' id='filter' value='<?php print html_escape($filter); ?>'></td>
						<td><?php print __('Section', 'cereus_ipam'); ?></td>
						<td>
							<select id='section_id' class='ui-state-default ui-corner-all'>
								<?php
								foreach ($section_dropdown as $k => $v) {
									print "<option value='" . $k . "'" . ($section_id == $k ? ' selected' : '') . ">" . html_escape($v) . "</option>\n";
								}
								?>
							</select>
						</td>
						<?php if (cereus_ipam_license_has_vlans()) { ?>
						<td><?php print __('VLAN', 'cereus_ipam'); ?></td>
						<td>
							<select id='vlan_id' class='ui-state-default ui-corner-all'>
								<option value='-1'<?php print ($vlan_id == '-1' ? ' selected' : ''); ?>><?php print __('All', 'cereus_ipam'); ?></option>
								<option value='0'<?php print ($vlan_id == '0' ? ' selected' : ''); ?>><?php print __('None', 'cereus_ipam'); ?></option>
								<?php
								$vlans = db_fetch_assoc("SELECT id, vlan_number, name FROM plugin_cereus_ipam_vlans ORDER BY vlan_number");
								if (cacti_sizeof($vlans)) foreach ($vlans as $v) {
									print "<option value='" . $v['id'] . "'" . ($vlan_id == $v['id'] ? ' selected' : '') . ">" . html_escape($v['vlan_number'] . ' - ' . $v['name']) . "</option>\n";
								}
								?>
							</select>
						</td>
						<?php } ?>
						<?php if (cereus_ipam_license_has_vrfs()) { ?>
						<td><?php print __('VRF', 'cereus_ipam'); ?></td>
						<td>
							<select id='vrf_id' class='ui-state-default ui-corner-all'>
								<option value='-1'<?php print ($vrf_id == '-1' ? ' selected' : ''); ?>><?php print __('All', 'cereus_ipam'); ?></option>
								<option value='0'<?php print ($vrf_id == '0' ? ' selected' : ''); ?>><?php print __('None', 'cereus_ipam'); ?></option>
								<?php
								$vrfs = db_fetch_assoc("SELECT id, name, rd FROM plugin_cereus_ipam_vrfs ORDER BY name");
								if (cacti_sizeof($vrfs)) foreach ($vrfs as $v) {
									$label = $v['name'] . (!empty($v['rd']) ? ' (' . $v['rd'] . ')' : '');
									print "<option value='" . $v['id'] . "'" . ($vrf_id == $v['id'] ? ' selected' : '') . ">" . html_escape($label) . "</option>\n";
								}
								?>
							</select>
						</td>
						<?php } ?>
						<?php if (cereus_ipam_license_has_multitenancy()) { ?>
						<td><?php print __('Tenant', 'cereus_ipam'); ?></td>
						<td>
							<select id='tenant_id' class='ui-state-default ui-corner-all'>
								<?php
								$tenant_dropdown_filter = cereus_ipam_get_tenants_dropdown();
								foreach ($tenant_dropdown_filter as $k => $v) {
									print "<option value='" . $k . "'" . ($tenant_id == $k ? ' selected' : '') . ">" . html_escape($v) . "</option>\n";
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
								$tag_dd_sub = cereus_ipam_get_tags_dropdown();
								foreach ($tag_dd_sub as $t_id => $t_name) {
									print "<option value='" . (int)$t_id . "'" . ($tag_filt == $t_id ? ' selected' : '') . ">" . html_escape($t_name) . "</option>\n";
								}
								?>
							</select>
						</td>
						<td>
							<span>
								<input type='button' class='ui-button' id='refresh' value='<?php print __esc('Go', 'cereus_ipam'); ?>'>
								<input type='button' class='ui-button' id='clear' value='<?php print __esc('Clear', 'cereus_ipam'); ?>'>
							</span>
						</td>
					</tr>
				</table>
			</form>
			<script type='text/javascript'>
			function applyFilter() {
				var url = 'cereus_ipam.php?header=false&filter=' + encodeURIComponent($('#filter').val())
					+ '&section_id=' + $('#section_id').val()
					+ '&vlan_id=' + ($('#vlan_id').length ? $('#vlan_id').val() : '-1')
					+ '&vrf_id=' + ($('#vrf_id').length ? $('#vrf_id').val() : '-1')
					+ '&tenant_id=' + ($('#tenant_id').length ? $('#tenant_id').val() : '-1')
					+ '&tag_id=' + $('#tag_id').val();
				loadPageNoHeader(url);
			}
			$(function() {
				$('#refresh').click(function() { applyFilter(); });
				$('#clear').click(function() { loadPageNoHeader('cereus_ipam.php?header=false&clear=1'); });
				$('#section_id').change(function() { applyFilter(); });
				$('#vlan_id').change(function() { applyFilter(); });
				$('#vrf_id').change(function() { applyFilter(); });
				$('#tenant_id').change(function() { applyFilter(); });
				$('#tag_id').change(function() { applyFilter(); });
				$('#filter').keypress(function(e) { if (e.which == 13) { applyFilter(); e.preventDefault(); } });
			});
			</script>
		</td>
	</tr>
	<?php
	html_end_box();

	/* Build SQL */
	$sql_where  = 'WHERE 1=1';
	$sql_params = array();

	if (!empty($filter)) {
		$safe = str_replace(array('%', '_'), array('\\%', '\\_'), $filter);
		$sql_where .= ' AND (s.subnet LIKE ? OR s.description LIKE ? OR s.gateway LIKE ?)';
		$sql_params[] = '%' . $safe . '%';
		$sql_params[] = '%' . $safe . '%';
		$sql_params[] = '%' . $safe . '%';
	}

	if ($section_id >= 0) {
		$sql_where .= ' AND s.section_id = ?';
		$sql_params[] = $section_id;
	}

	if ($vlan_id == '0') {
		$sql_where .= ' AND (s.vlan_id IS NULL OR s.vlan_id = 0)';
	} elseif ($vlan_id > 0) {
		$sql_where .= ' AND s.vlan_id = ?';
		$sql_params[] = $vlan_id;
	}

	if ($vrf_id == '0') {
		$sql_where .= ' AND (s.vrf_id IS NULL OR s.vrf_id = 0)';
	} elseif ($vrf_id > 0) {
		$sql_where .= ' AND s.vrf_id = ?';
		$sql_params[] = $vrf_id;
	}

	/* Tag filter */
	if ($tag_filt != '-1') {
		if ($tag_filt == '0') {
			$sql_where .= ' AND s.id NOT IN (SELECT object_id FROM plugin_cereus_ipam_tag_assignments WHERE object_type = \'subnet\')';
		} else {
			$sql_where .= ' AND s.id IN (SELECT object_id FROM plugin_cereus_ipam_tag_assignments WHERE object_type = \'subnet\' AND tag_id = ?)';
			$sql_params[] = $tag_filt;
		}
	}

	/* Tenant filter */
	if (cereus_ipam_license_has_multitenancy()) {
		list($sql_where, $sql_params) = cereus_ipam_apply_tenant_filter($sql_where, $sql_params, $tenant_id, 'sec');
	}

	$total_rows = db_fetch_cell_prepared(
		"SELECT COUNT(*) FROM plugin_cereus_ipam_subnets s
		LEFT JOIN plugin_cereus_ipam_sections sec ON sec.id = s.section_id
		$sql_where",
		$sql_params
	);

	$subnets = db_fetch_assoc_prepared(
		"SELECT s.*,
			sec.name AS section_name,
			(SELECT COUNT(*) FROM plugin_cereus_ipam_addresses WHERE subnet_id = s.id) AS addr_count
		FROM plugin_cereus_ipam_subnets s
		LEFT JOIN plugin_cereus_ipam_sections sec ON sec.id = s.section_id
		$sql_where
		ORDER BY s.subnet, s.mask
		LIMIT " . (($page - 1) * $rows) . ", $rows",
		$sql_params
	);

	/* Apply RBAC filtering to subnets */
	if (cereus_ipam_license_has_rbac()) {
		$subnets = cereus_ipam_filter_subnets_by_permission($subnets, 'view');
	}

	$nav = html_nav_bar('cereus_ipam.php', MAX_DISPLAY_PAGES, $page, $rows, $total_rows, 9, __('Subnets', 'cereus_ipam'));
	print $nav;

	form_start('cereus_ipam.php', 'chk');
	html_start_box('', '100%', '', '3', 'center', '');

	$display_text = array(
		'subnet'       => array('display' => __('Subnet', 'cereus_ipam'),      'sort' => 'ASC'),
		'description'  => array('display' => __('Description', 'cereus_ipam'), 'sort' => 'ASC'),
		'addr_count'   => array('display' => __('Addresses', 'cereus_ipam')),
		'nosort1'      => array('display' => __('Utilization', 'cereus_ipam')),
		'nosort2'      => array('display' => __('Threshold', 'cereus_ipam')),
		'gateway'      => array('display' => __('Gateway', 'cereus_ipam'),     'sort' => 'ASC'),
		'nosort3'      => array('display' => __('Actions', 'cereus_ipam')),
	);

	html_header_sort_checkbox($display_text, get_request_var('sort_column', 'subnet'), get_request_var('sort_direction', 'ASC'));

	/* Pre-compute subnet depth from parent_id chain for indentation */
	$depth_cache = array();
	if (cacti_sizeof($subnets)) {
		$all_subnets_map = array();
		$all_parents = db_fetch_assoc("SELECT id, parent_id FROM plugin_cereus_ipam_subnets");
		foreach ($all_parents as $sp) {
			$all_subnets_map[$sp['id']] = (int) $sp['parent_id'];
		}

		foreach ($subnets as $row) {
			$d = 0;
			$pid = (int) ($row['parent_id'] ?? 0);
			$visited = array();
			while ($pid > 0 && $d < 10 && !isset($visited[$pid])) {
				$visited[$pid] = true;
				$d++;
				$pid = $all_subnets_map[$pid] ?? 0;
			}
			$depth_cache[$row['id']] = $d;
		}
	}

	/* Group subnets by section for collapsible tree */
	$subnets_by_section = array();
	$section_order = array();
	if (cacti_sizeof($subnets)) {
		foreach ($subnets as $row) {
			$sid = (int) ($row['section_id'] ?? 0);
			if (!isset($subnets_by_section[$sid])) {
				$subnets_by_section[$sid] = array();
				$section_order[] = $sid;
			}
			$subnets_by_section[$sid][] = $row;
		}
	}

	/* Bulk-fetch tags for all displayed subnets */
	$subnet_tags = array();
	if (cacti_sizeof($subnets)) {
		$sids = array_column($subnets, 'id');
		$subnet_tags = cereus_ipam_get_bulk_tags('subnet', $sids);
	}

	/* Build section name lookup */
	$section_names = array(0 => __('No Section', 'cereus_ipam'));
	foreach ($sections as $s) {
		$section_names[$s['id']] = $s['name'];
	}

	if (cacti_sizeof($subnets)) {
		foreach ($section_order as $sid) {
			$section_subnets = $subnets_by_section[$sid];
			$sec_name = html_escape($section_names[$sid] ?? __('Unknown Section', 'cereus_ipam'));
			$sec_count = count($section_subnets);

			/* Section header row — collapsible */
			print '<tr class="tableHeader cipam-section-header" data-section="' . $sid . '" style="cursor:pointer;">';
			print '<td colspan="8" style="padding:6px 8px;font-weight:bold;background:#e8e8e8;border-bottom:1px solid #ccc;">';
			print '<span class="cipam-toggle" data-section="' . $sid . '">&#9660;</span> ';
			print '<i class="fa fa-folder-open" style="color:#f0ad4e;margin-right:5px;"></i>';
			print $sec_name . ' <span style="color:#999;font-weight:normal;">(' . $sec_count . ' ' . __('subnet(s)', 'cereus_ipam') . ')</span>';
			print '</td></tr>';

			foreach ($section_subnets as $row) {
				$util = cereus_ipam_subnet_utilization($row['id']);
				$depth = $depth_cache[$row['id']] ?? 0;
				$indent = ($depth > 0) ? str_repeat('&nbsp;&nbsp;&nbsp;', $depth) . '&#x2514; ' : '';

				/* Use manual TR with section class for collapsible grouping */
				static $cipam_row_i = 0;
				$cipam_row_i++;
				$tr_class = ($cipam_row_i % 2 == 0) ? 'even' : 'odd';
				print "<tr class='" . $tr_class . " selectable tableRow cipam-section-" . $sid . "' id='line" . $row['id'] . "'>";

				form_selectable_cell(
					$indent . '<a class="linkEditMain" href="cereus_ipam.php?action=edit&id=' . $row['id'] . '">'
					. html_escape($row['subnet'] . '/' . $row['mask']) . '</a>',
					$row['id']
				);
				$desc_html = html_escape($row['description']);
				if (isset($subnet_tags[$row['id']])) {
					$desc_html .= ' ' . cereus_ipam_render_tag_badges($subnet_tags[$row['id']]);
				}
				form_selectable_cell($desc_html, $row['id']);
				form_selectable_cell(
					'<a href="cereus_ipam_addresses.php?subnet_id=' . $row['id'] . '">' . $row['addr_count'] . ' / ' . $util['total'] . '</a>',
					$row['id']
				);

				/* Clickable utilization bar → links to visual map (Professional+) or address list */
				if (cereus_ipam_license_has_visual_map()) {
					$util_bar = '<a href="cereus_ipam_addresses.php?action=visual&subnet_id=' . $row['id'] . '" title="' . __esc('Open Visual Map', 'cereus_ipam') . '">'
						. cereus_ipam_utilization_bar($util['pct']) . '</a>';
				} else {
					$util_bar = '<a href="cereus_ipam_addresses.php?subnet_id=' . $row['id'] . '">'
						. cereus_ipam_utilization_bar($util['pct']) . '</a>';
				}
				form_selectable_cell($util_bar, $row['id']);

				/* Threshold status indicator */
				$thresh_status = cereus_ipam_threshold_status($row['id']);
				if ($thresh_status['threshold'] > 0) {
					if ($thresh_status['exceeded']) {
						$thresh_title = __esc('Utilization', 'cereus_ipam') . ' ' . $thresh_status['pct'] . '% ' . __esc('exceeds threshold', 'cereus_ipam') . ' ' . $thresh_status['threshold'] . '%';
						$thresh_html = '<span style="color:#e74c3c; font-weight:bold;" title="' . $thresh_title . '">&#9888; ' . $thresh_status['pct'] . '% / ' . $thresh_status['threshold'] . '%</span>';
					} else {
						$thresh_title = __esc('Utilization', 'cereus_ipam') . ' ' . $thresh_status['pct'] . '% ' . __esc('within threshold', 'cereus_ipam') . ' ' . $thresh_status['threshold'] . '%';
						$thresh_html = '<span style="color:#27ae60;" title="' . $thresh_title . '">&#10003; ' . $thresh_status['pct'] . '% / ' . $thresh_status['threshold'] . '%</span>';
					}
				} else {
					$thresh_html = '<span style="color:#999;">' . __('N/A', 'cereus_ipam') . '</span>';
				}
				form_selectable_cell($thresh_html, $row['id']);

				form_selectable_cell(html_escape($row['gateway'] ?? ''), $row['id']);

				/* Quick-action buttons */
				$actions_html = '<a href="cereus_ipam_addresses.php?subnet_id=' . $row['id'] . '" title="' . __esc('View Addresses', 'cereus_ipam') . '"><i class="fa fa-list"></i></a>';
				if (cereus_ipam_license_has_visual_map()) {
					$actions_html .= '&nbsp;&nbsp;<a href="cereus_ipam_addresses.php?action=visual&subnet_id=' . $row['id'] . '" title="' . __esc('Visual Map', 'cereus_ipam') . '"><i class="fa fa-th"></i></a>';
				}
				if (cereus_ipam_license_has_scanning()) {
					$actions_html .= '&nbsp;&nbsp;<a href="cereus_ipam_scan.php?subnet_id=' . $row['id'] . '" title="' . __esc('Scan Subnet', 'cereus_ipam') . '"><i class="fa fa-search"></i></a>';
					if (!empty($row['scan_enabled'])) {
						$actions_html .= '&nbsp;&nbsp;<span title="' . __esc('Scheduled scan enabled', 'cereus_ipam') . '" style="color:#27ae60;"><i class="fa fa-clock-o"></i></span>';
					}
				}
				form_selectable_cell($actions_html, $row['id'], '', 'text-align:center;');

				form_checkbox_cell($row['subnet'] . '/' . $row['mask'], $row['id']);
				form_end_row();
			}
		}
	} else {
		print '<tr><td colspan="8"><em>' . __('No subnets found. Create a section first, then add subnets.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box(false);
	print $nav;
	draw_actions_dropdown($subnet_actions);

	/* Collapsible section JavaScript */
	?>
	<script type='text/javascript'>
	$(function() {
		$('.cipam-section-header').click(function() {
			var sid = $(this).data('section');
			var rows = $('tr.cipam-section-' + sid);
			var toggle = $(this).find('.cipam-toggle');
			if (rows.first().is(':visible')) {
				rows.hide();
				toggle.html('&#9654;');
				$(this).find('.fa-folder-open').removeClass('fa-folder-open').addClass('fa-folder');
			} else {
				rows.show();
				toggle.html('&#9660;');
				$(this).find('.fa-folder').removeClass('fa-folder').addClass('fa-folder-open');
			}
		});
	});
	</script>
	<?php
}
