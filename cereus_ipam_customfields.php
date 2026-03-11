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
 | Cereus IPAM - Custom Field Definitions UI (Professional+)               |
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

/* Check license for Custom Fields feature */
if (!cereus_ipam_license_has_custom_fields() && $action !== '') {
	raise_message('cereus_ipam_lic', __('Custom field management requires a Professional license.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
	header('Location: cereus_ipam_customfields.php');
	exit;
}

switch ($action) {
	case 'save':
		cereus_ipam_cf_save();
		break;
	case 'actions':
		cereus_ipam_cf_actions();
		break;
	case 'edit':
		top_header();
		cereus_ipam_cf_edit();
		bottom_footer();
		break;
	default:
		top_header();
		cereus_ipam_cf_list();
		bottom_footer();
		break;
}

/* ==================== Save ==================== */

function cereus_ipam_cf_save() {
	if (!isset_request_var('save_component')) {
		return;
	}

	$id            = get_filter_request_var('id');
	$name          = cereus_ipam_sanitize_text(get_nfilter_request_var('name', ''), 64);
	$label         = cereus_ipam_sanitize_text(get_nfilter_request_var('label', ''), 255);
	$type          = get_nfilter_request_var('type', 'text');
	$options       = get_nfilter_request_var('options', '');
	$applies_to    = get_nfilter_request_var('applies_to', 'subnet');
	$required      = (isset_request_var('required') && get_nfilter_request_var('required') == 'on') ? 1 : 0;
	$display_order = get_filter_request_var('display_order', FILTER_VALIDATE_INT);

	$valid_types      = array('text', 'textarea', 'dropdown', 'checkbox', 'date', 'url');
	$valid_applies_to = array('subnet', 'address', 'vlan');

	/* Validate name slug */
	if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $name)) {
		raise_message('cereus_ipam_cf_name', __('Field name must start with a letter or underscore and contain only alphanumeric characters and underscores.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_customfields.php?action=edit&id=' . $id);
		exit;
	}

	/* Validate label */
	if (empty($label)) {
		raise_message('cereus_ipam_cf_label', __('Display label is required.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_customfields.php?action=edit&id=' . $id);
		exit;
	}

	/* Validate type */
	if (!in_array($type, $valid_types, true)) {
		raise_message('cereus_ipam_cf_type', __('Invalid field type.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_customfields.php?action=edit&id=' . $id);
		exit;
	}

	/* Validate applies_to */
	if (!in_array($applies_to, $valid_applies_to, true)) {
		raise_message('cereus_ipam_cf_applies', __('Invalid applies-to value.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_customfields.php?action=edit&id=' . $id);
		exit;
	}

	/* Validate display_order */
	if ($display_order === false || $display_order < 0) {
		$display_order = 0;
	}

	/* Sanitize options — only meaningful for dropdown */
	if ($type === 'dropdown') {
		$options = trim($options);
		if (!empty($options)) {
			$decoded = json_decode($options, true);
			if (!is_array($decoded)) {
				raise_message('cereus_ipam_cf_opts', __('Options must be a valid JSON array (e.g. ["Option A","Option B"]).', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
				header('Location: cereus_ipam_customfields.php?action=edit&id=' . $id);
				exit;
			}
			$options = json_encode($decoded);
		}
	} else {
		$options = '';
	}

	/* Check unique constraint: no duplicate (name, applies_to) for new fields or changed name/applies_to */
	if ($id > 0) {
		$existing = db_fetch_cell_prepared(
			"SELECT COUNT(*) FROM plugin_cereus_ipam_custom_fields WHERE name = ? AND applies_to = ? AND id != ?",
			array($name, $applies_to, $id)
		);
	} else {
		$existing = db_fetch_cell_prepared(
			"SELECT COUNT(*) FROM plugin_cereus_ipam_custom_fields WHERE name = ? AND applies_to = ?",
			array($name, $applies_to)
		);
	}

	if ($existing > 0) {
		raise_message('cereus_ipam_cf_dup', __('A custom field with this name already exists for the selected object type.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_customfields.php?action=edit&id=' . $id);
		exit;
	}

	if ($id > 0) {
		$old = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_custom_fields WHERE id = ?", array($id));
		db_execute_prepared("UPDATE plugin_cereus_ipam_custom_fields SET
			name = ?, label = ?, type = ?, options = ?, applies_to = ?, required = ?, display_order = ?
			WHERE id = ?",
			array($name, $label, $type, $options, $applies_to, $required, $display_order, $id));
		cereus_ipam_changelog_record('update', 'custom_field', $id, $old, array('name' => $name, 'label' => $label, 'type' => $type, 'applies_to' => $applies_to));
		$new_id = $id;
	} else {
		db_execute_prepared("INSERT INTO plugin_cereus_ipam_custom_fields
			(name, label, type, options, applies_to, required, display_order)
			VALUES (?, ?, ?, ?, ?, ?, ?)",
			array($name, $label, $type, $options, $applies_to, $required, $display_order));
		$new_id = db_fetch_insert_id();
		cereus_ipam_changelog_record('create', 'custom_field', $new_id, null, array('name' => $name, 'label' => $label, 'type' => $type, 'applies_to' => $applies_to));
	}

	raise_message('cereus_ipam_saved', __('Custom field saved.', 'cereus_ipam'), MESSAGE_LEVEL_INFO);
	header('Location: cereus_ipam_customfields.php');
	exit;
}

/* ==================== Bulk Actions ==================== */

function cereus_ipam_cf_actions() {
	global $actions;

	if (isset_request_var('selected_items')) {
		$selected_items = sanitize_unserialize_selected_items(get_nfilter_request_var('selected_items'));

		if ($selected_items !== false) {
			$drp_action = get_nfilter_request_var('drp_action');

			foreach ($selected_items as $id) {
				if (!is_numeric($id) || $id <= 0) continue;

				switch ($drp_action) {
					case '1':
						db_execute_prepared("DELETE FROM plugin_cereus_ipam_custom_fields WHERE id = ?", array($id));
						cereus_ipam_changelog_record('delete', 'custom_field', $id, null, null);
						break;
				}
			}
		}

		header('Location: cereus_ipam_customfields.php');
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
	form_start('cereus_ipam_customfields.php');
	html_start_box($actions[get_nfilter_request_var('drp_action')], '60%', '', '3', 'center', '');

	if (cacti_sizeof($item_array)) {
		foreach ($item_array as $id) {
			$row = db_fetch_row_prepared('SELECT name, label, applies_to FROM plugin_cereus_ipam_custom_fields WHERE id = ?', array($id));
			if (cacti_sizeof($row)) {
				print '<tr><td class="odd"><span class="deleteMarker">' . html_escape($row['label']) . ' (' . html_escape($row['name']) . ' / ' . html_escape($row['applies_to']) . ')</span></td></tr>';
			}
		}
	}

	print '<tr><td class="saveRow"><p>' . __('Are you sure you want to delete the selected custom field(s)?', 'cereus_ipam') . '</p></td></tr>';

	$save_html = "<input type='button' class='ui-button ui-corner-all ui-widget' value='" . __esc('Cancel', 'cereus_ipam') . "' onClick='cactiReturnTo(\"cereus_ipam_customfields.php\")'>&nbsp;";
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

function cereus_ipam_cf_edit() {
	$id = get_filter_request_var('id');

	if (!cereus_ipam_license_has_custom_fields()) {
		html_start_box(__('Custom Field Management', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr class="even"><td style="padding:8px 15px;"><em>' . __('Custom field management requires a Professional license.', 'cereus_ipam') . '</em></td></tr>';
		html_end_box();
		return;
	}

	if ($id > 0) {
		$cf = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_custom_fields WHERE id = ?", array($id));
		if (!cacti_sizeof($cf)) {
			raise_message('cereus_ipam_nf', __('Custom field not found.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
			header('Location: cereus_ipam_customfields.php');
			exit;
		}
		$header = __('Edit Custom Field: %s', html_escape($cf['label']), 'cereus_ipam');
	} else {
		$cf = array();
		$header = __('New Custom Field', 'cereus_ipam');
	}

	$type_array = array(
		'text'     => __('Text', 'cereus_ipam'),
		'textarea' => __('Textarea', 'cereus_ipam'),
		'dropdown' => __('Dropdown', 'cereus_ipam'),
		'checkbox' => __('Checkbox', 'cereus_ipam'),
		'date'     => __('Date', 'cereus_ipam'),
		'url'      => __('URL', 'cereus_ipam'),
	);

	$applies_to_array = array(
		'subnet'  => __('Subnet', 'cereus_ipam'),
		'address' => __('Address', 'cereus_ipam'),
		'vlan'    => __('VLAN', 'cereus_ipam'),
	);

	$fields = array(
		'cf_header' => array(
			'friendly_name' => __('Custom Field Settings', 'cereus_ipam'),
			'method'        => 'spacer',
		),
		'name' => array(
			'friendly_name' => __('Field Name (Slug)', 'cereus_ipam'),
			'description'   => __('Internal field name. Must start with a letter or underscore and contain only alphanumeric characters and underscores.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $cf['name'] ?? '',
			'max_length'    => 64,
			'size'          => 40,
		),
		'label' => array(
			'friendly_name' => __('Display Label', 'cereus_ipam'),
			'description'   => __('Human-readable label shown in the UI.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $cf['label'] ?? '',
			'max_length'    => 255,
			'size'          => 50,
		),
		'type' => array(
			'friendly_name' => __('Field Type', 'cereus_ipam'),
			'description'   => __('The data type for this custom field.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'value'         => $cf['type'] ?? 'text',
			'array'         => $type_array,
		),
		'options' => array(
			'friendly_name' => __('Dropdown Options', 'cereus_ipam'),
			'description'   => __('JSON array of choices for dropdown fields (e.g. ["Option A","Option B"]). Only used when type is Dropdown.', 'cereus_ipam'),
			'method'        => 'textarea',
			'value'         => $cf['options'] ?? '',
			'textarea_rows' => 3,
			'textarea_cols' => 60,
			'max_length'    => 65535,
		),
		'applies_to' => array(
			'friendly_name' => __('Applies To', 'cereus_ipam'),
			'description'   => __('The object type this field applies to.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'value'         => $cf['applies_to'] ?? 'subnet',
			'array'         => $applies_to_array,
		),
		'required' => array(
			'friendly_name' => __('Required', 'cereus_ipam'),
			'description'   => __('Whether this field must be filled in.', 'cereus_ipam'),
			'method'        => 'checkbox',
			'value'         => $cf['required'] ?? '0',
		),
		'display_order' => array(
			'friendly_name' => __('Display Order', 'cereus_ipam'),
			'description'   => __('Numeric sort order for displaying custom fields.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $cf['display_order'] ?? '0',
			'max_length'    => 4,
			'size'          => 8,
		),
	);

	form_start('cereus_ipam_customfields.php');
	html_start_box($header, '100%', '', '3', 'center', '');
	draw_edit_form(array(
		'config' => array('no_form_tag' => true),
		'fields' => $fields,
	));
	html_end_box();

	form_hidden_box('id', $id, '0');
	form_hidden_box('save_component', '1', '');
	form_save_button('cereus_ipam_customfields.php', 'return');
}

/* ==================== List View ==================== */

function cereus_ipam_cf_list() {
	global $actions;

	if (!cereus_ipam_license_has_custom_fields()) {
		html_start_box(__('Custom Field Management', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr class="even"><td style="padding:8px 15px;"><em>' . __('Custom field management requires a Professional license. Community tier does not support custom fields.', 'cereus_ipam') . '</em></td></tr>';
		html_end_box();
		return;
	}

	/* Filter handling */
	if (isset_request_var('clear')) {
		kill_session_var('sess_cipam_cf_filter');
		kill_session_var('sess_cipam_cf_rows');
		kill_session_var('sess_cipam_cf_page');
		unset_request_var('filter');
		unset_request_var('rows');
		unset_request_var('page');
	}

	load_current_session_value('filter', 'sess_cipam_cf_filter', '');
	load_current_session_value('rows',   'sess_cipam_cf_rows',   '-1');
	load_current_session_value('page',   'sess_cipam_cf_page',   '1');

	$filter = get_request_var('filter');
	$rows   = get_request_var('rows');
	$page   = get_request_var('page');

	if ($rows == -1) {
		$rows = read_config_option('num_rows_table');
	}
	$rows = max(1, (int) $rows);
	$page = max(1, (int) $page);

	/* Filter bar */
	html_start_box(__('Custom Fields', 'cereus_ipam'), '100%', '', '3', 'center', 'cereus_ipam_customfields.php?action=edit&id=0');
	?>
	<tr class='even'>
		<td>
			<form id='form_cipam_cf' action='cereus_ipam_customfields.php'>
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
				loadPageNoHeader('cereus_ipam_customfields.php?header=false&filter=' + encodeURIComponent($('#filter').val()));
			}
			$(function() {
				$('#refresh').click(function() { applyFilter(); });
				$('#clear').click(function() { loadPageNoHeader('cereus_ipam_customfields.php?header=false&clear=1'); });
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
		$sql_where .= ' AND (cf.name LIKE ? OR cf.label LIKE ?)';
		$sql_params[] = '%' . $safe . '%';
		$sql_params[] = '%' . $safe . '%';
	}

	$total_rows = db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_custom_fields cf $sql_where", $sql_params);

	$custom_fields = db_fetch_assoc_prepared(
		"SELECT cf.*
		FROM plugin_cereus_ipam_custom_fields cf
		$sql_where
		ORDER BY cf.display_order ASC, cf.label ASC
		LIMIT " . (($page - 1) * $rows) . ", $rows",
		$sql_params
	);

	$nav = html_nav_bar('cereus_ipam_customfields.php', MAX_DISPLAY_PAGES, $page, $rows, $total_rows, 7, __('Custom Fields', 'cereus_ipam'));
	print $nav;

	form_start('cereus_ipam_customfields.php', 'chk');
	html_start_box('', '100%', '', '3', 'center', '');

	$display_text = array(
		'label'         => array('display' => __('Label', 'cereus_ipam'),         'sort' => 'ASC'),
		'name'          => array('display' => __('Name (Slug)', 'cereus_ipam'),   'sort' => 'ASC'),
		'type'          => array('display' => __('Type', 'cereus_ipam'),          'sort' => 'ASC'),
		'applies_to'    => array('display' => __('Applies To', 'cereus_ipam'),    'sort' => 'ASC'),
		'required'      => array('display' => __('Required', 'cereus_ipam'),      'sort' => 'ASC'),
		'display_order' => array('display' => __('Display Order', 'cereus_ipam'), 'sort' => 'ASC'),
	);

	html_header_sort_checkbox($display_text, get_request_var('sort_column', 'display_order'), get_request_var('sort_direction', 'ASC'));

	if (cacti_sizeof($custom_fields)) {
		foreach ($custom_fields as $row) {
			form_alternate_row('line' . $row['id'], true);
			form_selectable_cell(
				'<a class="linkEditMain" href="cereus_ipam_customfields.php?action=edit&id=' . $row['id'] . '">'
				. html_escape($row['label']) . '</a>',
				$row['id']
			);
			form_selectable_cell(html_escape($row['name']), $row['id']);
			form_selectable_cell(html_escape(ucfirst($row['type'])), $row['id']);
			form_selectable_cell(html_escape(ucfirst($row['applies_to'])), $row['id']);
			form_selectable_cell($row['required'] ? __('Yes', 'cereus_ipam') : __('No', 'cereus_ipam'), $row['id']);
			form_selectable_cell($row['display_order'], $row['id']);
			form_checkbox_cell($row['label'], $row['id']);
			form_end_row();
		}
	} else {
		print '<tr><td colspan="7"><em>' . __('No custom fields found. Click the + to add one.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box(false);
	print $nav;
	draw_actions_dropdown($actions);
}
