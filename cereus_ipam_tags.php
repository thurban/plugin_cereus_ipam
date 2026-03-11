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
 | Cereus IPAM - Tag Management UI                                         |
 +-------------------------------------------------------------------------+
*/

chdir('../../');
include('./include/auth.php');
include_once('./plugins/cereus_ipam/includes/constants.php');
include_once('./plugins/cereus_ipam/lib/license_check.php');
include_once('./plugins/cereus_ipam/lib/validation.php');
include_once('./plugins/cereus_ipam/lib/changelog.php');
include_once('./plugins/cereus_ipam/lib/functions.php');

$actions = array(
	1 => __('Delete', 'cereus_ipam'),
);

$action = get_nfilter_request_var('action', '');

switch ($action) {
	case 'save':
		cereus_ipam_tag_save();
		break;
	case 'actions':
		cereus_ipam_tag_actions();
		break;
	case 'edit':
		top_header();
		cereus_ipam_tag_edit();
		bottom_footer();
		break;
	default:
		top_header();
		cereus_ipam_tag_list();
		bottom_footer();
		break;
}

/* ==================== Save ==================== */

function cereus_ipam_tag_save() {
	if (!isset_request_var('save_component')) {
		return;
	}

	$id          = get_filter_request_var('id');
	$name        = cereus_ipam_sanitize_text(get_nfilter_request_var('name', ''), 64);
	$color       = trim(get_nfilter_request_var('color', '#6c757d'));
	$description = cereus_ipam_sanitize_text(get_nfilter_request_var('description', ''), 255);

	/* Validate color format */
	if (!preg_match('/^#[0-9a-fA-F]{6}$/', $color)) {
		$color = '#6c757d';
	}

	/* Helper to preserve form data on validation failure */
	$form_data_tag = array(
		'name' => $name, 'color' => $color, 'description' => $description,
	);

	if (empty($name)) {
		$_SESSION['cipam_form_tag'] = $form_data_tag;
		raise_message('cereus_ipam_name', __('Tag name is required.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_tags.php?action=edit&id=' . $id);
		exit;
	}

	/* Check for duplicate name */
	$dup_sql = "SELECT COUNT(*) FROM plugin_cereus_ipam_tags WHERE name = ?";
	$dup_params = array($name);
	if ($id > 0) {
		$dup_sql .= " AND id != ?";
		$dup_params[] = $id;
	}
	if (db_fetch_cell_prepared($dup_sql, $dup_params) > 0) {
		$_SESSION['cipam_form_tag'] = $form_data_tag;
		raise_message('cereus_ipam_dup', __('A tag with this name already exists.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_tags.php?action=edit&id=' . $id);
		exit;
	}

	if ($id > 0) {
		$old = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_tags WHERE id = ?", array($id));
		db_execute_prepared("UPDATE plugin_cereus_ipam_tags SET name = ?, color = ?, description = ? WHERE id = ?",
			array($name, $color, $description, $id));
		cereus_ipam_changelog_record('update', 'setting', $id, $old, array('name' => $name, 'color' => $color));
	} else {
		db_execute_prepared("INSERT INTO plugin_cereus_ipam_tags (name, color, description) VALUES (?, ?, ?)",
			array($name, $color, $description));
		$new_id = db_fetch_insert_id();
		cereus_ipam_changelog_record('create', 'setting', $new_id, null, array('tag' => $name));
	}

	raise_message('cereus_ipam_saved', __('Tag saved.', 'cereus_ipam'), MESSAGE_LEVEL_INFO);
	header('Location: cereus_ipam_tags.php');
	exit;
}

/* ==================== Bulk Actions ==================== */

function cereus_ipam_tag_actions() {
	global $actions;

	if (isset_request_var('selected_items')) {
		$selected_items = sanitize_unserialize_selected_items(get_nfilter_request_var('selected_items'));

		if ($selected_items !== false) {
			$drp_action = get_nfilter_request_var('drp_action');

			foreach ($selected_items as $id) {
				if (!is_numeric($id) || $id <= 0) continue;

				switch ($drp_action) {
					case '1':
						db_execute_prepared("DELETE FROM plugin_cereus_ipam_tag_assignments WHERE tag_id = ?", array($id));
						db_execute_prepared("DELETE FROM plugin_cereus_ipam_tags WHERE id = ?", array($id));
						cereus_ipam_changelog_record('delete', 'setting', $id, null, null);
						break;
				}
			}
		}

		header('Location: cereus_ipam_tags.php');
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
	form_start('cereus_ipam_tags.php');
	html_start_box($actions[get_nfilter_request_var('drp_action')], '60%', '', '3', 'center', '');

	if (cacti_sizeof($item_array)) {
		foreach ($item_array as $id) {
			$row = db_fetch_row_prepared('SELECT name FROM plugin_cereus_ipam_tags WHERE id = ?', array($id));
			if (cacti_sizeof($row)) {
				print '<tr><td class="odd"><span class="deleteMarker">' . html_escape($row['name']) . '</span></td></tr>';
			}
		}
	}

	print '<tr><td class="saveRow"><p>' . __('Are you sure you want to delete the selected tag(s)? Assignments will be removed.', 'cereus_ipam') . '</p></td></tr>';

	$save_html = "<input type='button' class='ui-button ui-corner-all ui-widget' value='" . __esc('Cancel', 'cereus_ipam') . "' onClick='cactiReturnTo(\"cereus_ipam_tags.php\")'>&nbsp;";
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

function cereus_ipam_tag_edit() {
	$id = get_filter_request_var('id');

	if ($id > 0) {
		$tag = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_tags WHERE id = ?", array($id));
		if (!cacti_sizeof($tag)) {
			raise_message('cereus_ipam_nf', __('Tag not found.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
			header('Location: cereus_ipam_tags.php');
			exit;
		}
		$header = __('Edit Tag: %s', html_escape($tag['name']), 'cereus_ipam');
	} else {
		$tag = array();
		$header = __('New Tag', 'cereus_ipam');
	}

	/* Restore form data from session after validation error */
	if (isset($_SESSION['cipam_form_tag']) && is_array($_SESSION['cipam_form_tag'])) {
		$tag = array_merge($tag, $_SESSION['cipam_form_tag']);
		unset($_SESSION['cipam_form_tag']);
	}

	$fields = array(
		'tag_header' => array(
			'friendly_name' => __('Tag Settings', 'cereus_ipam'),
			'method'        => 'spacer',
		),
		'name' => array(
			'friendly_name' => __('Name', 'cereus_ipam'),
			'description'   => __('A short label for this tag (e.g., Production, DMZ, Legacy).', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $tag['name'] ?? '',
			'max_length'    => 64,
			'size'          => 30,
		),
		'color' => array(
			'friendly_name' => __('Color', 'cereus_ipam'),
			'description'   => __('Hex color code for the tag badge (e.g., #28a745).', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $tag['color'] ?? '#6c757d',
			'max_length'    => 7,
			'size'          => 10,
		),
		'description' => array(
			'friendly_name' => __('Description', 'cereus_ipam'),
			'description'   => __('Optional description.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $tag['description'] ?? '',
			'max_length'    => 255,
			'size'          => 60,
		),
	);

	form_start('cereus_ipam_tags.php');
	html_start_box($header, '100%', '', '3', 'center', '');
	draw_edit_form(array(
		'config' => array('no_form_tag' => true),
		'fields' => $fields,
	));

	/* Color preview */
	$preview_color = html_escape($tag['color'] ?? '#6c757d');
	print '<tr><td colspan="2" style="padding:5px 15px;">';
	print '<strong>' . __('Preview:', 'cereus_ipam') . '</strong> ';
	print '<span id="cipam_tag_preview" style="display:inline-block;padding:2px 8px;border-radius:3px;font-size:12px;'
		. 'background-color:' . $preview_color . ';color:#fff;">' . html_escape($tag['name'] ?? 'Tag') . '</span>';
	print '</td></tr>';

	html_end_box();

	form_hidden_box('id', $id, '0');
	form_hidden_box('save_component', '1', '');
	form_save_button('cereus_ipam_tags.php', 'return');

	?>
	<script type='text/javascript'>
	$(function() {
		function updatePreview() {
			var name = $('#name').val() || 'Tag';
			var color = $('#color').val() || '#6c757d';
			var r = parseInt(color.substr(1,2), 16) || 0;
			var g = parseInt(color.substr(3,2), 16) || 0;
			var b = parseInt(color.substr(5,2), 16) || 0;
			var textColor = ((r*299 + g*587 + b*114) / 1000) > 128 ? '#000' : '#fff';
			$('#cipam_tag_preview').css({'background-color': color, 'color': textColor}).text(name);
		}
		$('#name, #color').on('input change', updatePreview);
	});
	</script>
	<?php
}

/* ==================== List View ==================== */

function cereus_ipam_tag_list() {
	global $actions;

	$tags = db_fetch_assoc("SELECT t.*,
		(SELECT COUNT(*) FROM plugin_cereus_ipam_tag_assignments WHERE tag_id = t.id) AS usage_count
		FROM plugin_cereus_ipam_tags t ORDER BY t.name");

	form_start('cereus_ipam_tags.php', 'chk');
	html_start_box(__('Tags', 'cereus_ipam'), '100%', '', '3', 'center', 'cereus_ipam_tags.php?action=edit&id=0');

	$display_text = array(
		'name'        => array('display' => __('Name', 'cereus_ipam'),        'sort' => 'ASC'),
		'color'       => array('display' => __('Color', 'cereus_ipam')),
		'description' => array('display' => __('Description', 'cereus_ipam'), 'sort' => 'ASC'),
		'usage_count' => array('display' => __('Used By', 'cereus_ipam')),
	);

	html_header_sort_checkbox($display_text, get_request_var('sort_column', 'name'), get_request_var('sort_direction', 'ASC'));

	if (cacti_sizeof($tags)) {
		foreach ($tags as $row) {
			form_alternate_row('line' . $row['id'], true);
			form_selectable_cell(
				'<a class="linkEditMain" href="cereus_ipam_tags.php?action=edit&id=' . $row['id'] . '">'
				. html_escape($row['name']) . '</a>',
				$row['id']
			);
			form_selectable_cell(
				'<span style="display:inline-block;width:16px;height:16px;border-radius:3px;vertical-align:middle;'
				. 'background-color:' . html_escape($row['color']) . ';"></span> '
				. html_escape($row['color']),
				$row['id']
			);
			form_selectable_cell(html_escape($row['description'] ?? ''), $row['id']);
			form_selectable_cell($row['usage_count'] . ' ' . __('objects', 'cereus_ipam'), $row['id']);
			form_checkbox_cell($row['name'], $row['id']);
			form_end_row();
		}
	} else {
		print '<tr><td colspan="5"><em>' . __('No tags defined. Click the + to create one.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box(false);
	draw_actions_dropdown($actions);
}
