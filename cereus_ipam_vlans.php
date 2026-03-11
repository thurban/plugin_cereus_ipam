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
 | Cereus IPAM - VLAN Management UI (Professional+)                        |
 +-------------------------------------------------------------------------+
*/

chdir('../../');
include('./include/auth.php');
include_once('./plugins/cereus_ipam/includes/constants.php');
include_once('./plugins/cereus_ipam/lib/license_check.php');
include_once('./plugins/cereus_ipam/lib/validation.php');
include_once('./plugins/cereus_ipam/lib/changelog.php');
include_once('./plugins/cereus_ipam/lib/custom_fields.php');

$actions = array(
	1 => __('Delete', 'cereus_ipam'),
);

$action = get_nfilter_request_var('action', '');

/* Check license for VLAN feature */
if (!cereus_ipam_license_has_vlans() && $action !== '') {
	raise_message('cereus_ipam_lic', __('VLAN management requires a Professional license.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
	header('Location: cereus_ipam_vlans.php');
	exit;
}

switch ($action) {
	case 'save':
		cereus_ipam_vlan_save();
		break;
	case 'actions':
		cereus_ipam_vlan_actions();
		break;
	case 'edit':
		top_header();
		cereus_ipam_vlan_edit();
		bottom_footer();
		break;
	default:
		top_header();
		cereus_ipam_vlan_list();
		bottom_footer();
		break;
}

/* ==================== Save ==================== */

function cereus_ipam_vlan_save() {
	if (!isset_request_var('save_component')) {
		return;
	}

	$id          = get_filter_request_var('id');
	$vlan_number = get_filter_request_var('vlan_number', FILTER_VALIDATE_INT);
	$name        = cereus_ipam_sanitize_text(get_nfilter_request_var('name', ''), 255);
	$description = cereus_ipam_sanitize_text(get_nfilter_request_var('description', ''), 65535);

	/* Helper to preserve form data on validation failure */
	$form_data_vlan = array(
		'vlan_number' => $vlan_number, 'name' => $name, 'description' => $description,
	);

	if (!cereus_ipam_validate_vlan($vlan_number)) {
		$_SESSION['cipam_form_vlan'] = $form_data_vlan;
		raise_message('cereus_ipam_vlan', __('VLAN number must be between 1 and 4094.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_vlans.php?action=edit&id=' . $id);
		exit;
	}

	if (empty($name)) {
		$_SESSION['cipam_form_vlan'] = $form_data_vlan;
		raise_message('cereus_ipam_name', __('VLAN name is required.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_vlans.php?action=edit&id=' . $id);
		exit;
	}

	if ($id > 0) {
		$old = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_vlans WHERE id = ?", array($id));
		db_execute_prepared("UPDATE plugin_cereus_ipam_vlans SET
			vlan_number = ?, name = ?, description = ?
			WHERE id = ?",
			array($vlan_number, $name, $description, $id));
		cereus_ipam_changelog_record('update', 'vlan', $id, $old, array('vlan_number' => $vlan_number, 'name' => $name));
		$new_id = $id;
	} else {
		db_execute_prepared("INSERT INTO plugin_cereus_ipam_vlans
			(vlan_number, name, description)
			VALUES (?, ?, ?)",
			array($vlan_number, $name, $description));
		$new_id = db_fetch_insert_id();
		cereus_ipam_changelog_record('create', 'vlan', $new_id, null, array('vlan_number' => $vlan_number, 'name' => $name));
	}

	/* Save custom fields */
	if (cereus_ipam_license_has_custom_fields()) {
		$cf_json = cereus_ipam_save_custom_fields('vlan');
		if ($new_id > 0) {
			db_execute_prepared("UPDATE plugin_cereus_ipam_vlans SET custom_fields = ? WHERE id = ?",
				array($cf_json, $new_id));
		}
	}

	raise_message('cereus_ipam_saved', __('VLAN saved.', 'cereus_ipam'), MESSAGE_LEVEL_INFO);
	header('Location: cereus_ipam_vlans.php');
	exit;
}

/* ==================== Bulk Actions ==================== */

function cereus_ipam_vlan_actions() {
	global $actions;

	if (isset_request_var('selected_items')) {
		$selected_items = sanitize_unserialize_selected_items(get_nfilter_request_var('selected_items'));

		if ($selected_items !== false) {
			$drp_action = get_nfilter_request_var('drp_action');

			foreach ($selected_items as $id) {
				if (!is_numeric($id) || $id <= 0) continue;

				switch ($drp_action) {
					case '1':
						/* Unlink subnets from this VLAN first */
						db_execute_prepared("UPDATE plugin_cereus_ipam_subnets SET vlan_id = NULL WHERE vlan_id = ?", array($id));
						db_execute_prepared("DELETE FROM plugin_cereus_ipam_vlans WHERE id = ?", array($id));
						cereus_ipam_changelog_record('delete', 'vlan', $id, null, null);
						break;
				}
			}
		}

		header('Location: cereus_ipam_vlans.php');
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
	form_start('cereus_ipam_vlans.php');
	html_start_box($actions[get_nfilter_request_var('drp_action')], '60%', '', '3', 'center', '');

	if (cacti_sizeof($item_array)) {
		foreach ($item_array as $id) {
			$row = db_fetch_row_prepared('SELECT vlan_number, name FROM plugin_cereus_ipam_vlans WHERE id = ?', array($id));
			if (cacti_sizeof($row)) {
				print '<tr><td class="odd"><span class="deleteMarker">VLAN ' . html_escape($row['vlan_number']) . ' - ' . html_escape($row['name']) . '</span></td></tr>';
			}
		}
	}

	print '<tr><td class="saveRow"><p>' . __('Are you sure you want to delete the selected VLAN(s)?', 'cereus_ipam') . '</p></td></tr>';

	$save_html = "<input type='button' class='ui-button ui-corner-all ui-widget' value='" . __esc('Cancel', 'cereus_ipam') . "' onClick='cactiReturnTo(\"cereus_ipam_vlans.php\")'>&nbsp;";
	$save_html .= "<input type='submit' class='ui-button ui-corner-all ui-widget' value='" . __esc('Continue', 'cereus_ipam') . "'>";
	print "<tr><td class='saveRow'>$save_html</td></tr>";

	html_end_box();
	form_hidden_box('action', 'actions', '');
	form_hidden_box('selected_items', serialize($item_array), '');
	form_hidden_box('drp_action', get_nfilter_request_var('drp_action'), '');
	form_end();
	bottom_footer();
}

/* ==================== Edit Form ==================== */

function cereus_ipam_vlan_edit() {
	$id = get_filter_request_var('id');

	if (!cereus_ipam_license_has_vlans()) {
		html_start_box(__('VLAN Management', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr class="even"><td style="padding:8px 15px;"><em>' . __('VLAN management requires a Professional license.', 'cereus_ipam') . '</em></td></tr>';
		html_end_box();
		return;
	}

	if ($id > 0) {
		$vlan = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_vlans WHERE id = ?", array($id));
		if (!cacti_sizeof($vlan)) {
			raise_message('cereus_ipam_nf', __('VLAN not found.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
			header('Location: cereus_ipam_vlans.php');
			exit;
		}
		$header = __('Edit VLAN: %d - %s', $vlan['vlan_number'], html_escape($vlan['name']), 'cereus_ipam');
	} else {
		$vlan = array();
		$header = __('New VLAN', 'cereus_ipam');
	}

	/* Restore form data from session after validation error */
	if (isset($_SESSION['cipam_form_vlan']) && is_array($_SESSION['cipam_form_vlan'])) {
		$vlan = array_merge($vlan, $_SESSION['cipam_form_vlan']);
		unset($_SESSION['cipam_form_vlan']);
	}

	$fields = array(
		'vlan_header' => array(
			'friendly_name' => __('VLAN Settings', 'cereus_ipam'),
			'method'        => 'spacer',
		),
		'vlan_number' => array(
			'friendly_name' => __('VLAN Number', 'cereus_ipam'),
			'description'   => __('VLAN ID (1-4094).', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $vlan['vlan_number'] ?? '',
			'max_length'    => 4,
			'size'          => 8,
		),
		'name' => array(
			'friendly_name' => __('Name', 'cereus_ipam'),
			'description'   => __('A descriptive name for this VLAN.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $vlan['name'] ?? '',
			'max_length'    => 255,
			'size'          => 50,
		),
		'description' => array(
			'friendly_name' => __('Description', 'cereus_ipam'),
			'description'   => __('Optional description.', 'cereus_ipam'),
			'method'        => 'textarea',
			'value'         => $vlan['description'] ?? '',
			'textarea_rows' => 3,
			'textarea_cols' => 60,
			'max_length'    => 65535,
		),
	);

	/* Custom fields (Professional+) */
	if (cereus_ipam_license_has_custom_fields()) {
		$cf_values = json_decode($vlan['custom_fields'] ?? '{}', true);
		if (!is_array($cf_values)) $cf_values = array();
		$cf_fields = cereus_ipam_render_custom_fields('vlan', $cf_values);
		if (cacti_sizeof($cf_fields)) {
			$fields['cf_spacer'] = array(
				'friendly_name' => __('Custom Fields', 'cereus_ipam'),
				'method' => 'spacer',
			);
			$fields = array_merge($fields, $cf_fields);
		}
	}

	form_start('cereus_ipam_vlans.php');
	html_start_box($header, '100%', '', '3', 'center', '');
	draw_edit_form(array(
		'config' => array('no_form_tag' => true),
		'fields' => $fields,
	));
	html_end_box();

	/* Show linked subnets for existing VLANs */
	if ($id > 0) {
		$linked = db_fetch_assoc_prepared("SELECT s.id, s.subnet, s.mask, s.description, sec.name AS section_name
			FROM plugin_cereus_ipam_subnets s
			LEFT JOIN plugin_cereus_ipam_sections sec ON sec.id = s.section_id
			WHERE s.vlan_id = ?
			ORDER BY s.subnet",
			array($id));

		html_start_box(__('Linked Subnets', 'cereus_ipam'), '100%', '', '3', 'center', '');
		if (cacti_sizeof($linked)) {
			$display_text = array(
				array('display' => __('Subnet', 'cereus_ipam'), 'align' => 'left'),
				array('display' => __('Section', 'cereus_ipam'), 'align' => 'left'),
				array('display' => __('Description', 'cereus_ipam'), 'align' => 'left'),
			);
			html_header($display_text);

			foreach ($linked as $ls) {
				form_alternate_row('ls_' . $ls['id']);
				form_selectable_cell(
					'<a href="cereus_ipam.php?action=edit&id=' . $ls['id'] . '">' . html_escape($ls['subnet'] . '/' . $ls['mask']) . '</a>',
					$ls['id']
				);
				form_selectable_cell(html_escape($ls['section_name'] ?? ''), $ls['id']);
				form_selectable_cell(html_escape($ls['description'] ?? ''), $ls['id']);
				form_end_row();
			}
		} else {
			print '<tr><td colspan="3"><em>' . __('No subnets linked to this VLAN.', 'cereus_ipam') . '</em></td></tr>';
		}
		html_end_box();
	}

	form_hidden_box('id', $id, '0');
	form_hidden_box('save_component', '1', '');
	form_save_button('cereus_ipam_vlans.php', 'return');
}

/* ==================== List View ==================== */

function cereus_ipam_vlan_list() {
	global $actions;

	if (!cereus_ipam_license_has_vlans()) {
		html_start_box(__('VLAN Management', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr class="even"><td style="padding:8px 15px;"><em>' . __('VLAN management requires a Professional license. Community tier supports subnet management only.', 'cereus_ipam') . '</em></td></tr>';
		html_end_box();
		return;
	}

	/* Filter handling */
	if (isset_request_var('clear')) {
		kill_session_var('sess_cipam_vlan_filter');
		kill_session_var('sess_cipam_vlan_rows');
		kill_session_var('sess_cipam_vlan_page');
		unset_request_var('filter');
		unset_request_var('rows');
		unset_request_var('page');
	}

	load_current_session_value('filter', 'sess_cipam_vlan_filter', '');
	load_current_session_value('rows',   'sess_cipam_vlan_rows',   '-1');
	load_current_session_value('page',   'sess_cipam_vlan_page',   '1');

	$filter = get_request_var('filter');
	$rows   = get_request_var('rows');
	$page   = get_request_var('page');

	if ($rows == -1) {
		$rows = read_config_option('num_rows_table');
	}
	$rows = max(1, (int) $rows);
	$page = max(1, (int) $page);

	/* Filter bar */
	html_start_box(__('VLANs', 'cereus_ipam'), '100%', '', '3', 'center', 'cereus_ipam_vlans.php?action=edit&id=0');
	?>
	<tr class='even'>
		<td>
			<form id='form_cipam_vlan' action='cereus_ipam_vlans.php'>
				<table class='filterTable'>
					<tr>
						<td><?php print __('Search', 'cereus_ipam'); ?></td>
						<td><input type='text' class='ui-state-default ui-corner-all' id='filter' value='<?php print html_escape($filter); ?>'></td>
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
				loadPageNoHeader('cereus_ipam_vlans.php?header=false&filter=' + encodeURIComponent($('#filter').val()));
			}
			$(function() {
				$('#refresh').click(function() { applyFilter(); });
				$('#clear').click(function() { loadPageNoHeader('cereus_ipam_vlans.php?header=false&clear=1'); });
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
		$sql_where .= ' AND (v.name LIKE ? OR v.description LIKE ? OR v.vlan_number LIKE ?)';
		$sql_params[] = '%' . $safe . '%';
		$sql_params[] = '%' . $safe . '%';
		$sql_params[] = '%' . $safe . '%';
	}

	$total_rows = db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_vlans v $sql_where", $sql_params);

	$vlans = db_fetch_assoc_prepared(
		"SELECT v.*,
			(SELECT COUNT(*) FROM plugin_cereus_ipam_subnets WHERE vlan_id = v.id) AS subnet_count
		FROM plugin_cereus_ipam_vlans v
		$sql_where
		ORDER BY v.vlan_number ASC
		LIMIT " . (($page - 1) * $rows) . ", $rows",
		$sql_params
	);

	$nav = html_nav_bar('cereus_ipam_vlans.php', MAX_DISPLAY_PAGES, $page, $rows, $total_rows, 5, __('VLANs', 'cereus_ipam'));
	print $nav;

	form_start('cereus_ipam_vlans.php', 'chk');
	html_start_box('', '100%', '', '3', 'center', '');

	$display_text = array(
		'vlan_number'  => array('display' => __('VLAN ID', 'cereus_ipam'),     'sort' => 'ASC'),
		'name'         => array('display' => __('Name', 'cereus_ipam'),        'sort' => 'ASC'),
		'description'  => array('display' => __('Description', 'cereus_ipam'), 'sort' => 'ASC'),
		'subnet_count' => array('display' => __('Subnets', 'cereus_ipam')),
	);

	html_header_sort_checkbox($display_text, get_request_var('sort_column', 'vlan_number'), get_request_var('sort_direction', 'ASC'));

	if (cacti_sizeof($vlans)) {
		foreach ($vlans as $row) {
			form_alternate_row('line' . $row['id'], true);
			form_selectable_cell(
				'<a class="linkEditMain" href="cereus_ipam_vlans.php?action=edit&id=' . $row['id'] . '">'
				. html_escape($row['vlan_number']) . '</a>',
				$row['id']
			);
			form_selectable_cell(html_escape($row['name']), $row['id']);
			form_selectable_cell(html_escape($row['description'] ?? ''), $row['id']);
			form_selectable_cell($row['subnet_count'], $row['id']);
			form_checkbox_cell($row['name'], $row['id']);
			form_end_row();
		}
	} else {
		print '<tr><td colspan="5"><em>' . __('No VLANs found. Click the + to add one.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box(false);
	print $nav;
	draw_actions_dropdown($actions);
}
