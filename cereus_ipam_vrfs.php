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
 | Cereus IPAM - VRF Management UI (Professional+)                         |
 +-------------------------------------------------------------------------+
*/

chdir('../../');
include('./include/auth.php');
include_once('./plugins/cereus_ipam/includes/constants.php');
include_once('./plugins/cereus_ipam/lib/license_check.php');
include_once('./plugins/cereus_ipam/lib/validation.php');
include_once('./plugins/cereus_ipam/lib/changelog.php');

$actions = array(
	1 => __('Delete', 'cereus_ipam'),
);

$action = get_nfilter_request_var('action', '');

/* Check license for VRF feature */
if (!cereus_ipam_license_has_vrfs() && $action !== '') {
	raise_message('cereus_ipam_lic', __('VRF management requires a Professional license.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
	header('Location: cereus_ipam_vrfs.php');
	exit;
}

switch ($action) {
	case 'save':
		cereus_ipam_vrf_save();
		break;
	case 'actions':
		cereus_ipam_vrf_actions();
		break;
	case 'edit':
		top_header();
		cereus_ipam_vrf_edit();
		bottom_footer();
		break;
	default:
		top_header();
		cereus_ipam_vrf_list();
		bottom_footer();
		break;
}

/* ==================== Save ==================== */

function cereus_ipam_vrf_save() {
	if (!isset_request_var('save_component')) {
		return;
	}

	$id          = get_filter_request_var('id');
	$name        = cereus_ipam_sanitize_text(get_nfilter_request_var('name', ''), 255);
	$rd          = cereus_ipam_sanitize_text(get_nfilter_request_var('rd', ''), 32);
	$description = cereus_ipam_sanitize_text(get_nfilter_request_var('description', ''), 65535);

	/* Helper to preserve form data on validation failure */
	$form_data_vrf = array(
		'name' => $name, 'rd' => $rd, 'description' => $description,
	);

	if (empty($name)) {
		$_SESSION['cipam_form_vrf'] = $form_data_vrf;
		raise_message('cereus_ipam_name', __('VRF name is required.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_vrfs.php?action=edit&id=' . $id);
		exit;
	}

	/* Validate RD format if provided (e.g. 65000:100 or 10.0.0.1:100) */
	if (!empty($rd) && !preg_match('/^[\d.:]+$/', $rd)) {
		$_SESSION['cipam_form_vrf'] = $form_data_vrf;
		raise_message('cereus_ipam_rd', __('Route Distinguisher format is invalid.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_vrfs.php?action=edit&id=' . $id);
		exit;
	}

	if ($id > 0) {
		$old = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_vrfs WHERE id = ?", array($id));
		db_execute_prepared("UPDATE plugin_cereus_ipam_vrfs SET
			name = ?, rd = ?, description = ?
			WHERE id = ?",
			array($name, $rd, $description, $id));
		cereus_ipam_changelog_record('update', 'vrf', $id, $old, array('name' => $name, 'rd' => $rd));
		$new_id = $id;
	} else {
		/* Check for duplicate RD */
		if (!empty($rd)) {
			$exists = db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_vrfs WHERE rd = ?", array($rd));
			if ($exists > 0) {
				$_SESSION['cipam_form_vrf'] = $form_data_vrf;
				raise_message('cereus_ipam_rd_dup', __('A VRF with this Route Distinguisher already exists.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
				header('Location: cereus_ipam_vrfs.php?action=edit&id=0');
				exit;
			}
		}

		db_execute_prepared("INSERT INTO plugin_cereus_ipam_vrfs
			(name, rd, description)
			VALUES (?, ?, ?)",
			array($name, $rd, $description));
		$new_id = db_fetch_insert_id();
		cereus_ipam_changelog_record('create', 'vrf', $new_id, null, array('name' => $name, 'rd' => $rd));
	}

	raise_message('cereus_ipam_saved', __('VRF saved.', 'cereus_ipam'), MESSAGE_LEVEL_INFO);
	header('Location: cereus_ipam_vrfs.php');
	exit;
}

/* ==================== Bulk Actions ==================== */

function cereus_ipam_vrf_actions() {
	global $actions;

	if (isset_request_var('selected_items')) {
		$selected_items = sanitize_unserialize_selected_items(get_nfilter_request_var('selected_items'));

		if ($selected_items !== false) {
			$drp_action = get_nfilter_request_var('drp_action');

			foreach ($selected_items as $id) {
				if (!is_numeric($id) || $id <= 0) continue;

				switch ($drp_action) {
					case '1':
						/* Unlink subnets from this VRF first */
						db_execute_prepared("UPDATE plugin_cereus_ipam_subnets SET vrf_id = NULL WHERE vrf_id = ?", array($id));
						db_execute_prepared("DELETE FROM plugin_cereus_ipam_vrfs WHERE id = ?", array($id));
						cereus_ipam_changelog_record('delete', 'vrf', $id, null, null);
						break;
				}
			}
		}

		header('Location: cereus_ipam_vrfs.php');
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
	form_start('cereus_ipam_vrfs.php');
	html_start_box($actions[get_nfilter_request_var('drp_action')], '60%', '', '3', 'center', '');

	if (cacti_sizeof($item_array)) {
		foreach ($item_array as $id) {
			$row = db_fetch_row_prepared('SELECT name, rd FROM plugin_cereus_ipam_vrfs WHERE id = ?', array($id));
			if (cacti_sizeof($row)) {
				$label = html_escape($row['name']);
				if (!empty($row['rd'])) {
					$label .= ' (RD: ' . html_escape($row['rd']) . ')';
				}
				print '<tr><td class="odd"><span class="deleteMarker">' . $label . '</span></td></tr>';
			}
		}
	}

	print '<tr><td class="saveRow"><p>' . __('Are you sure you want to delete the selected VRF(s)? Linked subnets will be unlinked.', 'cereus_ipam') . '</p></td></tr>';

	$save_html = "<input type='button' class='ui-button ui-corner-all ui-widget' value='" . __esc('Cancel', 'cereus_ipam') . "' onClick='cactiReturnTo(\"cereus_ipam_vrfs.php\")'>&nbsp;";
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

function cereus_ipam_vrf_edit() {
	$id = get_filter_request_var('id');

	if (!cereus_ipam_license_has_vrfs()) {
		html_start_box(__('VRF Management', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr class="even"><td style="padding:8px 15px;"><em>' . __('VRF management requires a Professional license.', 'cereus_ipam') . '</em></td></tr>';
		html_end_box();
		return;
	}

	if ($id > 0) {
		$vrf = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_vrfs WHERE id = ?", array($id));
		if (!cacti_sizeof($vrf)) {
			raise_message('cereus_ipam_nf', __('VRF not found.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
			header('Location: cereus_ipam_vrfs.php');
			exit;
		}
		$header = __('Edit VRF: %s', html_escape($vrf['name']), 'cereus_ipam');
	} else {
		$vrf = array();
		$header = __('New VRF', 'cereus_ipam');
	}

	/* Restore form data from session after validation error */
	if (isset($_SESSION['cipam_form_vrf']) && is_array($_SESSION['cipam_form_vrf'])) {
		$vrf = array_merge($vrf, $_SESSION['cipam_form_vrf']);
		unset($_SESSION['cipam_form_vrf']);
	}

	$fields = array(
		'vrf_header' => array(
			'friendly_name' => __('VRF Settings', 'cereus_ipam'),
			'method'        => 'spacer',
		),
		'name' => array(
			'friendly_name' => __('Name', 'cereus_ipam'),
			'description'   => __('A descriptive name for this VRF instance.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $vrf['name'] ?? '',
			'max_length'    => 255,
			'size'          => 50,
		),
		'rd' => array(
			'friendly_name' => __('Route Distinguisher', 'cereus_ipam'),
			'description'   => __('The RD uniquely identifies this VRF (e.g. 65000:100 or 10.0.0.1:100). Optional but recommended.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $vrf['rd'] ?? '',
			'max_length'    => 32,
			'size'          => 30,
		),
		'description' => array(
			'friendly_name' => __('Description', 'cereus_ipam'),
			'description'   => __('Optional description of this VRF.', 'cereus_ipam'),
			'method'        => 'textarea',
			'value'         => $vrf['description'] ?? '',
			'textarea_rows' => 3,
			'textarea_cols' => 60,
			'max_length'    => 65535,
		),
	);

	form_start('cereus_ipam_vrfs.php');
	html_start_box($header, '100%', '', '3', 'center', '');
	draw_edit_form(array(
		'config' => array('no_form_tag' => true),
		'fields' => $fields,
	));
	html_end_box();

	/* Show linked subnets for existing VRFs */
	if ($id > 0) {
		$linked = db_fetch_assoc_prepared("SELECT s.id, s.subnet, s.mask, s.description, sec.name AS section_name
			FROM plugin_cereus_ipam_subnets s
			LEFT JOIN plugin_cereus_ipam_sections sec ON sec.id = s.section_id
			WHERE s.vrf_id = ?
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
			print '<tr><td colspan="3"><em>' . __('No subnets linked to this VRF. Assign a VRF when editing a subnet.', 'cereus_ipam') . '</em></td></tr>';
		}
		html_end_box();
	}

	form_hidden_box('id', $id, '0');
	form_hidden_box('save_component', '1', '');
	form_save_button('cereus_ipam_vrfs.php', 'return');
}

/* ==================== List View ==================== */

function cereus_ipam_vrf_list() {
	global $actions;

	if (!cereus_ipam_license_has_vrfs()) {
		html_start_box(__('VRF Management', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr class="even"><td style="padding:8px 15px;"><em>' . __('VRF management requires a Professional license. VRFs allow overlapping address spaces across different routing domains.', 'cereus_ipam') . '</em></td></tr>';
		html_end_box();
		return;
	}

	/* Filter handling */
	if (isset_request_var('clear')) {
		kill_session_var('sess_cipam_vrf_filter');
		kill_session_var('sess_cipam_vrf_rows');
		kill_session_var('sess_cipam_vrf_page');
		unset_request_var('filter');
		unset_request_var('rows');
		unset_request_var('page');
	}

	load_current_session_value('filter', 'sess_cipam_vrf_filter', '');
	load_current_session_value('rows',   'sess_cipam_vrf_rows',   '-1');
	load_current_session_value('page',   'sess_cipam_vrf_page',   '1');

	$filter = get_request_var('filter');
	$rows   = get_request_var('rows');
	$page   = get_request_var('page');

	if ($rows == -1) {
		$rows = read_config_option('num_rows_table');
	}
	$rows = max(1, (int) $rows);
	$page = max(1, (int) $page);

	/* Filter bar */
	html_start_box(__('VRFs', 'cereus_ipam'), '100%', '', '3', 'center', 'cereus_ipam_vrfs.php?action=edit&id=0');
	?>
	<tr class='even'>
		<td>
			<form id='form_cipam_vrf' action='cereus_ipam_vrfs.php'>
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
				loadPageNoHeader('cereus_ipam_vrfs.php?header=false&filter=' + encodeURIComponent($('#filter').val()));
			}
			$(function() {
				$('#refresh').click(function() { applyFilter(); });
				$('#clear').click(function() { loadPageNoHeader('cereus_ipam_vrfs.php?header=false&clear=1'); });
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
		$sql_where .= ' AND (v.name LIKE ? OR v.rd LIKE ? OR v.description LIKE ?)';
		$sql_params[] = '%' . $safe . '%';
		$sql_params[] = '%' . $safe . '%';
		$sql_params[] = '%' . $safe . '%';
	}

	$total_rows = db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_vrfs v $sql_where", $sql_params);

	$vrfs = db_fetch_assoc_prepared(
		"SELECT v.*,
			(SELECT COUNT(*) FROM plugin_cereus_ipam_subnets WHERE vrf_id = v.id) AS subnet_count
		FROM plugin_cereus_ipam_vrfs v
		$sql_where
		ORDER BY v.name ASC
		LIMIT " . (($page - 1) * $rows) . ", $rows",
		$sql_params
	);

	$nav = html_nav_bar('cereus_ipam_vrfs.php', MAX_DISPLAY_PAGES, $page, $rows, $total_rows, 5, __('VRFs', 'cereus_ipam'));
	print $nav;

	form_start('cereus_ipam_vrfs.php', 'chk');
	html_start_box('', '100%', '', '3', 'center', '');

	$display_text = array(
		'name'         => array('display' => __('Name', 'cereus_ipam'),                    'sort' => 'ASC'),
		'rd'           => array('display' => __('Route Distinguisher', 'cereus_ipam'),     'sort' => 'ASC'),
		'description'  => array('display' => __('Description', 'cereus_ipam'),             'sort' => 'ASC'),
		'subnet_count' => array('display' => __('Subnets', 'cereus_ipam')),
	);

	html_header_sort_checkbox($display_text, get_request_var('sort_column', 'name'), get_request_var('sort_direction', 'ASC'));

	if (cacti_sizeof($vrfs)) {
		foreach ($vrfs as $row) {
			form_alternate_row('line' . $row['id'], true);
			form_selectable_cell(
				'<a class="linkEditMain" href="cereus_ipam_vrfs.php?action=edit&id=' . $row['id'] . '">'
				. html_escape($row['name']) . '</a>',
				$row['id']
			);
			form_selectable_cell(html_escape($row['rd'] ?? ''), $row['id']);
			form_selectable_cell(html_escape($row['description'] ?? ''), $row['id']);
			form_selectable_cell($row['subnet_count'], $row['id']);
			form_checkbox_cell($row['name'], $row['id']);
			form_end_row();
		}
	} else {
		print '<tr><td colspan="5"><em>' . __('No VRFs found. Click the + to add one.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box(false);
	print $nav;
	draw_actions_dropdown($actions);
}
