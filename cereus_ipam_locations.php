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
 | Cereus IPAM - Rack/Location Visualization UI (Enterprise)               |
 +-------------------------------------------------------------------------+
*/

chdir('../../');
include('./include/auth.php');
include_once('./plugins/cereus_ipam/includes/constants.php');
include_once('./plugins/cereus_ipam/lib/license_check.php');
include_once('./plugins/cereus_ipam/lib/validation.php');
include_once('./plugins/cereus_ipam/lib/functions.php');
include_once('./plugins/cereus_ipam/lib/changelog.php');

/* Enterprise license gate */
if (!cereus_ipam_license_has_locations()) {
	raise_message('cereus_ipam_license', __('Rack/Location Visualization requires an Enterprise license.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
	header('Location: cereus_ipam.php');
	exit;
}

$actions = array(
	1 => __('Delete', 'cereus_ipam'),
);

$location_types = array(
	'site'     => __('Site', 'cereus_ipam'),
	'building' => __('Building', 'cereus_ipam'),
	'floor'    => __('Floor', 'cereus_ipam'),
	'room'     => __('Room', 'cereus_ipam'),
	'rack'     => __('Rack', 'cereus_ipam'),
);

$action = get_nfilter_request_var('action', '');

switch ($action) {
	case 'save':
		cereus_ipam_location_save();
		break;
	case 'actions':
		cereus_ipam_location_actions();
		break;
	case 'edit':
		top_header();
		cereus_ipam_location_edit();
		bottom_footer();
		break;
	default:
		top_header();
		cereus_ipam_location_list();
		bottom_footer();
		break;
}

/* ==================== Save ==================== */

function cereus_ipam_location_save() {
	if (!isset_request_var('save_component')) {
		return;
	}

	$id            = get_filter_request_var('id');
	$name          = cereus_ipam_sanitize_text(get_nfilter_request_var('name', ''), 255);
	$description   = cereus_ipam_sanitize_text(get_nfilter_request_var('description', ''), 65535);
	$parent_id     = get_filter_request_var('parent_id', FILTER_VALIDATE_INT);
	$type          = get_nfilter_request_var('type', 'site');
	$display_order = get_filter_request_var('display_order', FILTER_VALIDATE_INT);

	if ($parent_id === false || $parent_id < 0) {
		$parent_id = 0;
	}
	if ($display_order === false || $display_order < 0) {
		$display_order = 0;
	}

	/* Validate name */
	if (empty($name)) {
		raise_message('cereus_ipam_name', __('Location name is required.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_locations.php?action=edit&id=' . $id);
		exit;
	}

	/* Validate type */
	$valid_types = array('site', 'building', 'floor', 'room', 'rack');
	if (!in_array($type, $valid_types)) {
		$type = 'site';
	}

	/* Prevent self-referencing parent */
	if ($id > 0 && $parent_id == $id) {
		raise_message('cereus_ipam_parent', __('A location cannot be its own parent.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_locations.php?action=edit&id=' . $id);
		exit;
	}

	/* Prevent circular parent reference */
	if ($id > 0 && $parent_id > 0) {
		$check_id = $parent_id;
		$max_depth = 20;
		$depth = 0;
		while ($check_id > 0 && $depth < $max_depth) {
			if ($check_id == $id) {
				raise_message('cereus_ipam_circular', __('Circular parent reference detected.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
				header('Location: cereus_ipam_locations.php?action=edit&id=' . $id);
				exit;
			}
			$check_id = db_fetch_cell_prepared("SELECT parent_id FROM plugin_cereus_ipam_locations WHERE id = ?", array($check_id));
			$depth++;
		}
	}

	if ($id > 0) {
		$old = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_locations WHERE id = ?", array($id));
		db_execute_prepared("UPDATE plugin_cereus_ipam_locations SET
			name = ?, description = ?, parent_id = ?, type = ?, display_order = ?
			WHERE id = ?",
			array($name, $description, $parent_id, $type, $display_order, $id));
		cereus_ipam_changelog_record('update', 'setting', $id, $old, array('name' => $name, 'type' => 'location'));
		$new_id = $id;
	} else {
		db_execute_prepared("INSERT INTO plugin_cereus_ipam_locations
			(name, description, parent_id, type, display_order)
			VALUES (?, ?, ?, ?, ?)",
			array($name, $description, $parent_id, $type, $display_order));
		$new_id = db_fetch_insert_id();
		cereus_ipam_changelog_record('create', 'setting', $new_id, null, array('name' => $name, 'type' => 'location'));
	}

	raise_message('cereus_ipam_saved', __('Location saved.', 'cereus_ipam'), MESSAGE_LEVEL_INFO);
	header('Location: cereus_ipam_locations.php');
	exit;
}

/* ==================== Bulk Actions ==================== */

function cereus_ipam_location_actions() {
	global $actions;

	if (isset_request_var('selected_items')) {
		$selected_items = sanitize_unserialize_selected_items(get_nfilter_request_var('selected_items'));

		if ($selected_items !== false) {
			$drp_action = get_nfilter_request_var('drp_action');

			foreach ($selected_items as $id) {
				if (!is_numeric($id) || $id <= 0) continue;

				switch ($drp_action) {
					case '1': /* delete */
						$old = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_locations WHERE id = ?", array($id));
						/* Reparent children to this location's parent */
						$parent_id = isset($old['parent_id']) ? $old['parent_id'] : 0;
						db_execute_prepared("UPDATE plugin_cereus_ipam_locations SET parent_id = ? WHERE parent_id = ?", array($parent_id, $id));
						/* Unlink addresses from this location */
						db_execute_prepared("UPDATE plugin_cereus_ipam_addresses SET location_id = NULL WHERE location_id = ?", array($id));
						/* Delete the location */
						db_execute_prepared("DELETE FROM plugin_cereus_ipam_locations WHERE id = ?", array($id));
						if (cacti_sizeof($old)) {
							cereus_ipam_changelog_record('delete', 'setting', $id, $old, array('type' => 'location'));
						}
						break;
				}
			}
		}

		header('Location: cereus_ipam_locations.php');
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
	form_start('cereus_ipam_locations.php');
	html_start_box($actions[get_nfilter_request_var('drp_action')], '60%', '', '3', 'center', '');

	if (cacti_sizeof($item_array)) {
		foreach ($item_array as $id) {
			$row = db_fetch_row_prepared('SELECT name, type FROM plugin_cereus_ipam_locations WHERE id = ?', array($id));
			if (cacti_sizeof($row)) {
				print '<tr><td class="odd"><span class="deleteMarker">' . html_escape($row['name']) . ' [' . html_escape(ucfirst($row['type'])) . ']</span></td></tr>';
			}
		}
	}

	print '<tr><td class="saveRow"><p>' . __('Are you sure you want to delete the selected location(s)? Child locations will be reparented and addresses will be unlinked.', 'cereus_ipam') . '</p></td></tr>';

	$save_html = "<input type='button' class='ui-button ui-corner-all ui-widget' value='" . __esc('Cancel', 'cereus_ipam') . "' onClick='cactiReturnTo(\"cereus_ipam_locations.php\")'>&nbsp;";
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

function cereus_ipam_location_edit() {
	global $location_types;

	$id = get_filter_request_var('id');

	if ($id > 0) {
		$location = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_locations WHERE id = ?", array($id));
		if (!cacti_sizeof($location)) {
			raise_message('cereus_ipam_nf', __('Location not found.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
			header('Location: cereus_ipam_locations.php');
			exit;
		}
		$header = __('Edit Location: %s', html_escape($location['name']), 'cereus_ipam');
	} else {
		$location = array();
		$header = __('New Location', 'cereus_ipam');
	}

	/* Build parent dropdown excluding self and descendants */
	$parent_dropdown = cereus_ipam_get_locations_dropdown();
	if ($id > 0) {
		/* Remove self from parent dropdown */
		unset($parent_dropdown[$id]);
		/* Remove descendants to prevent circular references */
		$tree = cereus_ipam_get_locations_tree($id);
		foreach ($tree as $child) {
			unset($parent_dropdown[$child['id']]);
		}
	}

	$fields = array(
		'location_header' => array(
			'friendly_name' => __('Location Settings', 'cereus_ipam'),
			'method'        => 'spacer',
		),
		'name' => array(
			'friendly_name' => __('Name', 'cereus_ipam'),
			'description'   => __('A descriptive name for this location.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $location['name'] ?? '',
			'max_length'    => 255,
			'size'          => 60,
		),
		'description' => array(
			'friendly_name' => __('Description', 'cereus_ipam'),
			'description'   => __('Optional description of this location.', 'cereus_ipam'),
			'method'        => 'textarea',
			'value'         => $location['description'] ?? '',
			'textarea_rows' => 3,
			'textarea_cols' => 60,
			'max_length'    => 65535,
		),
		'parent_id' => array(
			'friendly_name' => __('Parent Location', 'cereus_ipam'),
			'description'   => __('Select a parent location for hierarchy. Leave as None for a top-level location.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'value'         => $location['parent_id'] ?? '0',
			'array'         => $parent_dropdown,
		),
		'type' => array(
			'friendly_name' => __('Type', 'cereus_ipam'),
			'description'   => __('The type of this location (site, building, floor, room, or rack).', 'cereus_ipam'),
			'method'        => 'drop_array',
			'value'         => $location['type'] ?? 'site',
			'array'         => $location_types,
		),
		'display_order' => array(
			'friendly_name' => __('Display Order', 'cereus_ipam'),
			'description'   => __('Sort order among siblings. Lower numbers appear first.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $location['display_order'] ?? '0',
			'max_length'    => 10,
			'size'          => 10,
		),
	);

	form_start('cereus_ipam_locations.php');
	html_start_box($header, '100%', '', '3', 'center', '');
	draw_edit_form(array(
		'config' => array('no_form_tag' => true),
		'fields' => $fields,
	));
	html_end_box();

	/* Show addresses assigned to this location */
	if ($id > 0) {
		$addr_count = db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_addresses WHERE location_id = ?", array($id));
		if ($addr_count > 0) {
			html_start_box(__('Assigned Addresses (%s)', $addr_count, 'cereus_ipam'), '100%', '', '3', 'center', '');

			$addresses = db_fetch_assoc_prepared(
				"SELECT a.ip, a.hostname, a.state, a.subnet_id,
					CONCAT(s.subnet, '/', s.mask) AS cidr
				FROM plugin_cereus_ipam_addresses a
				LEFT JOIN plugin_cereus_ipam_subnets s ON s.id = a.subnet_id
				WHERE a.location_id = ?
				ORDER BY INET_ATON(a.ip)
				LIMIT 50",
				array($id)
			);

			$display_text = array(
				array('display' => __('IP Address', 'cereus_ipam'), 'align' => 'left'),
				array('display' => __('Hostname', 'cereus_ipam'),   'align' => 'left'),
				array('display' => __('Subnet', 'cereus_ipam'),     'align' => 'left'),
				array('display' => __('State', 'cereus_ipam'),      'align' => 'left'),
			);
			html_header($display_text);

			foreach ($addresses as $a) {
				form_alternate_row();
				print '<td><a class="linkEditMain" href="cereus_ipam_addresses.php?action=edit&id=0&subnet_id=' . $a['subnet_id'] . '">' . html_escape($a['ip']) . '</a></td>';
				print '<td>' . html_escape($a['hostname'] ?? '') . '</td>';
				print '<td>' . html_escape($a['cidr'] ?? '') . '</td>';
				print '<td>' . html_escape(ucfirst($a['state'])) . '</td>';
				form_end_row();
			}

			if ($addr_count > 50) {
				print '<tr><td colspan="4"><em>' . __('Showing first 50 of %s addresses.', $addr_count, 'cereus_ipam') . '</em></td></tr>';
			}

			html_end_box();
		}
	}

	form_hidden_box('id', $id, '0');
	form_hidden_box('save_component', '1', '');
	form_save_button('cereus_ipam_locations.php', 'return');
}

/* ==================== List View ==================== */

function cereus_ipam_location_list() {
	global $actions, $location_types;

	/* Filter handling */
	if (isset_request_var('clear')) {
		kill_session_var('sess_cipam_location_filter');
		kill_session_var('sess_cipam_location_type');
		kill_session_var('sess_cipam_location_rows');
		kill_session_var('sess_cipam_location_page');
		unset_request_var('filter');
		unset_request_var('type_filter');
		unset_request_var('rows');
		unset_request_var('page');
	}

	load_current_session_value('filter',      'sess_cipam_location_filter', '');
	load_current_session_value('type_filter', 'sess_cipam_location_type',   '-1');
	load_current_session_value('rows',        'sess_cipam_location_rows',   '-1');
	load_current_session_value('page',        'sess_cipam_location_page',   '1');

	$filter      = get_request_var('filter');
	$type_filter = get_request_var('type_filter');
	$rows        = get_request_var('rows');
	$page        = get_request_var('page');

	if ($rows == -1) {
		$rows = read_config_option('num_rows_table');
	}
	$rows = max(1, (int) $rows);
	$page = max(1, (int) $page);

	/* Filter bar */
	html_start_box(__('Locations', 'cereus_ipam'), '100%', '', '3', 'center', 'cereus_ipam_locations.php?action=edit&id=0');
	?>
	<tr class='even'>
		<td>
			<form id='form_cipam_location' action='cereus_ipam_locations.php'>
				<table class='filterTable'>
					<tr>
						<td><?php print __('Search', 'cereus_ipam'); ?></td>
						<td><input type='text' class='ui-state-default ui-corner-all' id='filter' value='<?php print html_escape($filter); ?>'></td>
						<td><?php print __('Type', 'cereus_ipam'); ?></td>
						<td>
							<select id='type_filter'>
								<option value='-1' <?php print ($type_filter == '-1' ? 'selected' : ''); ?>><?php print __('All', 'cereus_ipam'); ?></option>
								<?php
								foreach ($location_types as $k => $v) {
									print "<option value='" . html_escape($k) . "'" . ($type_filter == $k ? ' selected' : '') . ">" . html_escape($v) . "</option>\n";
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
				loadPageNoHeader('cereus_ipam_locations.php?header=false'
					+ '&filter=' + encodeURIComponent($('#filter').val())
					+ '&type_filter=' + $('#type_filter').val());
			}
			$(function() {
				$('#refresh').click(function() { applyFilter(); });
				$('#clear').click(function() { loadPageNoHeader('cereus_ipam_locations.php?header=false&clear=1'); });
				$('#type_filter').change(function() { applyFilter(); });
				$('#filter').keypress(function(e) { if (e.which == 13) { applyFilter(); e.preventDefault(); } });
			});
			</script>
		</td>
	</tr>
	<?php
	html_end_box();

	/* Use the tree approach to show hierarchy */
	$all_locations = cereus_ipam_get_locations_tree();

	/* Apply filters to the flat tree */
	$filtered = array();
	foreach ($all_locations as $loc) {
		$match = true;

		if (!empty($filter)) {
			$safe = strtolower($filter);
			if (strpos(strtolower($loc['name']), $safe) === false &&
				strpos(strtolower($loc['description'] ?? ''), $safe) === false) {
				$match = false;
			}
		}

		if ($type_filter != '-1' && $loc['type'] != $type_filter) {
			$match = false;
		}

		if ($match) {
			$filtered[] = $loc;
		}
	}

	$total_rows = count($filtered);

	/* Paginate */
	$start = ($page - 1) * $rows;
	$paged = array_slice($filtered, $start, $rows);

	$nav = html_nav_bar('cereus_ipam_locations.php', MAX_DISPLAY_PAGES, $page, $rows, $total_rows, 7, __('Locations', 'cereus_ipam'));
	print $nav;

	form_start('cereus_ipam_locations.php', 'chk');
	html_start_box('', '100%', '', '3', 'center', '');

	$display_text = array(
		'name'          => array('display' => __('Name', 'cereus_ipam'),        'sort' => 'ASC'),
		'nosort_type'   => array('display' => __('Type', 'cereus_ipam')),
		'nosort_parent' => array('display' => __('Parent', 'cereus_ipam')),
		'description'   => array('display' => __('Description', 'cereus_ipam'), 'sort' => 'ASC'),
		'nosort_addrs'  => array('display' => __('Addresses', 'cereus_ipam')),
	);

	html_header_sort_checkbox($display_text, get_request_var('sort_column', 'name'), get_request_var('sort_direction', 'ASC'));

	if (cacti_sizeof($paged)) {
		/* Pre-fetch parent names and address counts */
		$parent_names = array();
		$all_locs = db_fetch_assoc("SELECT id, name FROM plugin_cereus_ipam_locations");
		foreach ($all_locs as $l) {
			$parent_names[$l['id']] = $l['name'];
		}

		foreach ($paged as $row) {
			form_alternate_row('line' . $row['id'], true);

			/* Indented name */
			$indent = str_repeat('-- ', $row['depth']);
			form_selectable_cell(
				'<a class="linkEditMain" href="cereus_ipam_locations.php?action=edit&id=' . $row['id'] . '">'
				. html_escape($indent . $row['name']) . '</a>',
				$row['id']
			);

			/* Type */
			form_selectable_cell(html_escape(ucfirst($row['type'])), $row['id']);

			/* Parent */
			$parent_name = '';
			if ($row['parent_id'] > 0 && isset($parent_names[$row['parent_id']])) {
				$parent_name = $parent_names[$row['parent_id']];
			}
			form_selectable_cell(html_escape($parent_name), $row['id']);

			/* Description */
			form_selectable_cell(html_escape($row['description'] ?? ''), $row['id']);

			/* Address count */
			$addr_count = db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_addresses WHERE location_id = ?", array($row['id']));
			form_selectable_cell($addr_count, $row['id']);

			form_checkbox_cell($row['name'], $row['id']);
			form_end_row();
		}
	} else {
		print '<tr><td colspan="6"><em>' . __('No locations found. Click the + to add one.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box(false);
	print $nav;
	draw_actions_dropdown($actions);
}
