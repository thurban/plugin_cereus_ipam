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
 | Cereus IPAM - Maintenance Window Management UI (Enterprise)             |
 +-------------------------------------------------------------------------+
*/

chdir('../../');
include('./include/auth.php');
include_once('./plugins/cereus_ipam/includes/constants.php');
include_once('./plugins/cereus_ipam/lib/license_check.php');
include_once('./plugins/cereus_ipam/lib/validation.php');
include_once('./plugins/cereus_ipam/lib/changelog.php');
include_once('./plugins/cereus_ipam/lib/maintenance.php');

$actions = array(
	1 => __('Delete', 'cereus_ipam'),
);

$action = get_nfilter_request_var('action', '');

/* Check license for maintenance feature */
if (!cereus_ipam_license_has_maintenance() && $action !== '') {
	raise_message('cereus_ipam_lic', __('Maintenance windows require an Enterprise license.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
	header('Location: cereus_ipam_maintenance.php');
	exit;
}

switch ($action) {
	case 'save':
		cereus_ipam_maintenance_save();
		break;
	case 'actions':
		cereus_ipam_maintenance_actions();
		break;
	case 'edit':
		top_header();
		cereus_ipam_maintenance_edit();
		bottom_footer();
		break;
	default:
		top_header();
		cereus_ipam_maintenance_list();
		bottom_footer();
		break;
}

/* ==================== Save ==================== */

function cereus_ipam_maintenance_save() {
	if (!isset_request_var('save_component')) {
		return;
	}

	$id              = get_filter_request_var('id');
	$title           = cereus_ipam_sanitize_text(get_nfilter_request_var('title', ''), 255);
	$description     = cereus_ipam_sanitize_text(get_nfilter_request_var('description', ''), 65535);
	$start_time      = get_nfilter_request_var('start_time', '');
	$end_time        = get_nfilter_request_var('end_time', '');
	$subnet_ids      = cereus_ipam_sanitize_text(get_nfilter_request_var('subnet_ids', ''), 65535);
	$suppress_scans  = isset_request_var('suppress_scans') ? 1 : 0;
	$suppress_alerts = isset_request_var('suppress_alerts') ? 1 : 0;

	/* Validate title */
	if (empty($title)) {
		raise_message('cereus_ipam_title', __('Title is required.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_maintenance.php?action=edit&id=' . $id);
		exit;
	}

	/* Validate start_time format */
	$start_ts = strtotime($start_time);
	if ($start_ts === false || !preg_match('/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}$/', trim($start_time))) {
		raise_message('cereus_ipam_start', __('Start time must be a valid datetime (YYYY-MM-DD HH:MM:SS).', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_maintenance.php?action=edit&id=' . $id);
		exit;
	}

	/* Validate end_time format */
	$end_ts = strtotime($end_time);
	if ($end_ts === false || !preg_match('/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}$/', trim($end_time))) {
		raise_message('cereus_ipam_end', __('End time must be a valid datetime (YYYY-MM-DD HH:MM:SS).', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_maintenance.php?action=edit&id=' . $id);
		exit;
	}

	/* Validate end_time is after start_time */
	if ($end_ts <= $start_ts) {
		raise_message('cereus_ipam_range', __('End time must be after start time.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_maintenance.php?action=edit&id=' . $id);
		exit;
	}

	$created_by = isset($_SESSION['sess_user_id']) ? (int) $_SESSION['sess_user_id'] : null;

	if ($id > 0) {
		$old = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_maintenance WHERE id = ?", array($id));
		db_execute_prepared("UPDATE plugin_cereus_ipam_maintenance SET
			title = ?, description = ?, start_time = ?, end_time = ?,
			subnet_ids = ?, suppress_scans = ?, suppress_alerts = ?
			WHERE id = ?",
			array($title, $description, trim($start_time), trim($end_time), $subnet_ids, $suppress_scans, $suppress_alerts, $id));
		cereus_ipam_changelog_record('update', 'setting', $id, $old, array('title' => $title, 'type' => 'maintenance'));
		$new_id = $id;
	} else {
		db_execute_prepared("INSERT INTO plugin_cereus_ipam_maintenance
			(title, description, start_time, end_time, subnet_ids, suppress_scans, suppress_alerts, created_by)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
			array($title, $description, trim($start_time), trim($end_time), $subnet_ids, $suppress_scans, $suppress_alerts, $created_by));
		$new_id = db_fetch_insert_id();
		cereus_ipam_changelog_record('create', 'setting', $new_id, null, array('title' => $title, 'type' => 'maintenance'));
	}

	raise_message('cereus_ipam_saved', __('Maintenance window saved.', 'cereus_ipam'), MESSAGE_LEVEL_INFO);
	header('Location: cereus_ipam_maintenance.php');
	exit;
}

/* ==================== Bulk Actions ==================== */

function cereus_ipam_maintenance_actions() {
	global $actions;

	if (isset_request_var('selected_items')) {
		$selected_items = sanitize_unserialize_selected_items(get_nfilter_request_var('selected_items'));

		if ($selected_items !== false) {
			$drp_action = get_nfilter_request_var('drp_action');

			foreach ($selected_items as $id) {
				if (!is_numeric($id) || $id <= 0) continue;

				switch ($drp_action) {
					case '1':
						db_execute_prepared("DELETE FROM plugin_cereus_ipam_maintenance WHERE id = ?", array($id));
						cereus_ipam_changelog_record('delete', 'setting', $id, null, array('type' => 'maintenance'));
						break;
				}
			}
		}

		header('Location: cereus_ipam_maintenance.php');
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
	form_start('cereus_ipam_maintenance.php');
	html_start_box($actions[get_nfilter_request_var('drp_action')], '60%', '', '3', 'center', '');

	if (cacti_sizeof($item_array)) {
		foreach ($item_array as $id) {
			$row = db_fetch_row_prepared('SELECT title FROM plugin_cereus_ipam_maintenance WHERE id = ?', array($id));
			if (cacti_sizeof($row)) {
				print '<tr><td class="odd"><span class="deleteMarker">' . html_escape($row['title']) . '</span></td></tr>';
			}
		}
	}

	print '<tr><td class="saveRow"><p>' . __('Are you sure you want to delete the selected maintenance window(s)?', 'cereus_ipam') . '</p></td></tr>';

	$save_html = "<input type='button' class='ui-button ui-corner-all ui-widget' value='" . __esc('Cancel', 'cereus_ipam') . "' onClick='cactiReturnTo(\"cereus_ipam_maintenance.php\")'>&nbsp;";
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

function cereus_ipam_maintenance_edit() {
	$id = get_filter_request_var('id');

	if (!cereus_ipam_license_has_maintenance()) {
		html_start_box(__('Maintenance Windows', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr class="even"><td style="padding:8px 15px;"><em>' . __('Maintenance windows require an Enterprise license.', 'cereus_ipam') . '</em></td></tr>';
		html_end_box();
		return;
	}

	if ($id > 0) {
		$maint = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_maintenance WHERE id = ?", array($id));
		if (!cacti_sizeof($maint)) {
			raise_message('cereus_ipam_nf', __('Maintenance window not found.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
			header('Location: cereus_ipam_maintenance.php');
			exit;
		}
		$header = __('Edit Maintenance Window: %s', html_escape($maint['title']), 'cereus_ipam');
	} else {
		$maint = array();
		$header = __('New Maintenance Window', 'cereus_ipam');
	}

	$fields = array(
		'maint_header' => array(
			'friendly_name' => __('Maintenance Window Settings', 'cereus_ipam'),
			'method'        => 'spacer',
		),
		'title' => array(
			'friendly_name' => __('Title', 'cereus_ipam'),
			'description'   => __('A descriptive title for this maintenance window.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $maint['title'] ?? '',
			'max_length'    => 255,
			'size'          => 60,
		),
		'description' => array(
			'friendly_name' => __('Description', 'cereus_ipam'),
			'description'   => __('Optional description or notes.', 'cereus_ipam'),
			'method'        => 'textarea',
			'value'         => $maint['description'] ?? '',
			'textarea_rows' => 3,
			'textarea_cols' => 60,
			'max_length'    => 65535,
		),
		'start_time' => array(
			'friendly_name' => __('Start Time', 'cereus_ipam'),
			'description'   => __('When the maintenance window begins.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $maint['start_time'] ?? '',
			'max_length'    => 19,
			'size'          => 25,
			'placeholder'   => 'YYYY-MM-DD HH:MM:SS',
		),
		'end_time' => array(
			'friendly_name' => __('End Time', 'cereus_ipam'),
			'description'   => __('When the maintenance window ends.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $maint['end_time'] ?? '',
			'max_length'    => 19,
			'size'          => 25,
			'placeholder'   => 'YYYY-MM-DD HH:MM:SS',
		),
		'subnet_ids' => array(
			'friendly_name' => __('Subnet IDs', 'cereus_ipam'),
			'description'   => __('Comma-separated subnet IDs, or \'all\' for all subnets.', 'cereus_ipam'),
			'method'        => 'textarea',
			'value'         => $maint['subnet_ids'] ?? '',
			'textarea_rows' => 2,
			'textarea_cols' => 60,
			'max_length'    => 65535,
		),
		'suppress_scans' => array(
			'friendly_name' => __('Suppress Scans', 'cereus_ipam'),
			'description'   => __('When checked, scheduled network scans will be skipped for affected subnets during this window.', 'cereus_ipam'),
			'method'        => 'checkbox',
			'value'         => $maint['suppress_scans'] ?? '1',
			'default'       => 'on',
		),
		'suppress_alerts' => array(
			'friendly_name' => __('Suppress Alerts', 'cereus_ipam'),
			'description'   => __('When checked, threshold alerts will be suppressed for affected subnets during this window.', 'cereus_ipam'),
			'method'        => 'checkbox',
			'value'         => $maint['suppress_alerts'] ?? '1',
			'default'       => 'on',
		),
	);

	form_start('cereus_ipam_maintenance.php');
	html_start_box($header, '100%', '', '3', 'center', '');
	draw_edit_form(array(
		'config' => array('no_form_tag' => true),
		'fields' => $fields,
	));
	html_end_box();

	form_hidden_box('id', $id, '0');
	form_hidden_box('save_component', '1', '');
	form_save_button('cereus_ipam_maintenance.php', 'return');
}

/* ==================== List View ==================== */

function cereus_ipam_maintenance_list() {
	global $actions;

	if (!cereus_ipam_license_has_maintenance()) {
		html_start_box(__('Maintenance Windows', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr class="even"><td style="padding:8px 15px;"><em>' . __('Maintenance windows require an Enterprise license. This feature allows you to suppress scans and alerts during planned maintenance periods.', 'cereus_ipam') . '</em></td></tr>';
		html_end_box();
		return;
	}

	/* Filter handling */
	if (isset_request_var('clear')) {
		kill_session_var('sess_cipam_maint_filter');
		kill_session_var('sess_cipam_maint_rows');
		kill_session_var('sess_cipam_maint_page');
		unset_request_var('filter');
		unset_request_var('rows');
		unset_request_var('page');
	}

	load_current_session_value('filter', 'sess_cipam_maint_filter', '');
	load_current_session_value('rows',   'sess_cipam_maint_rows',   '-1');
	load_current_session_value('page',   'sess_cipam_maint_page',   '1');

	$filter = get_request_var('filter');
	$rows   = get_request_var('rows');
	$page   = get_request_var('page');

	if ($rows == -1) {
		$rows = read_config_option('num_rows_table');
	}
	$rows = max(1, (int) $rows);
	$page = max(1, (int) $page);

	/* Filter bar */
	html_start_box(__('Maintenance Windows', 'cereus_ipam'), '100%', '', '3', 'center', 'cereus_ipam_maintenance.php?action=edit&id=0');
	?>
	<tr class='even'>
		<td>
			<form id='form_cipam_maint' action='cereus_ipam_maintenance.php'>
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
				loadPageNoHeader('cereus_ipam_maintenance.php?header=false&filter=' + encodeURIComponent($('#filter').val()));
			}
			$(function() {
				$('#refresh').click(function() { applyFilter(); });
				$('#clear').click(function() { loadPageNoHeader('cereus_ipam_maintenance.php?header=false&clear=1'); });
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
		$sql_where .= ' AND (m.title LIKE ? OR m.description LIKE ? OR m.subnet_ids LIKE ?)';
		$sql_params[] = '%' . $safe . '%';
		$sql_params[] = '%' . $safe . '%';
		$sql_params[] = '%' . $safe . '%';
	}

	$total_rows = db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_maintenance m $sql_where", $sql_params);

	$windows = db_fetch_assoc_prepared(
		"SELECT m.*
		FROM plugin_cereus_ipam_maintenance m
		$sql_where
		ORDER BY m.start_time DESC
		LIMIT " . (($page - 1) * $rows) . ", $rows",
		$sql_params
	);

	$nav = html_nav_bar('cereus_ipam_maintenance.php', MAX_DISPLAY_PAGES, $page, $rows, $total_rows, 8, __('Maintenance Windows', 'cereus_ipam'));
	print $nav;

	form_start('cereus_ipam_maintenance.php', 'chk');
	html_start_box('', '100%', '', '3', 'center', '');

	$display_text = array(
		'title'           => array('display' => __('Title', 'cereus_ipam'),           'sort' => 'ASC'),
		'start_time'      => array('display' => __('Start Time', 'cereus_ipam'),      'sort' => 'ASC'),
		'end_time'        => array('display' => __('End Time', 'cereus_ipam'),        'sort' => 'ASC'),
		'subnet_ids'      => array('display' => __('Subnets', 'cereus_ipam')),
		'nosort_status'   => array('display' => __('Status', 'cereus_ipam')),
		'suppress_scans'  => array('display' => __('Suppress Scans', 'cereus_ipam')),
		'suppress_alerts' => array('display' => __('Suppress Alerts', 'cereus_ipam')),
	);

	html_header_sort_checkbox($display_text, get_request_var('sort_column', 'start_time'), get_request_var('sort_direction', 'DESC'));

	$now = date('Y-m-d H:i:s');

	if (cacti_sizeof($windows)) {
		foreach ($windows as $row) {
			/* Determine status */
			if ($now >= $row['start_time'] && $now <= $row['end_time']) {
				$status = '<span style="color: #27ae60; font-weight: bold;">' . __('Active', 'cereus_ipam') . '</span>';
			} elseif ($now < $row['start_time']) {
				$status = '<span style="color: #2980b9; font-weight: bold;">' . __('Scheduled', 'cereus_ipam') . '</span>';
			} else {
				$status = '<span style="color: #95a5a6;">' . __('Expired', 'cereus_ipam') . '</span>';
			}

			/* Format subnet_ids for display */
			$subnets_display = html_escape($row['subnet_ids'] ?? '');
			if (strlen($subnets_display) > 50) {
				$subnets_display = substr($subnets_display, 0, 47) . '...';
			}

			form_alternate_row('line' . $row['id'], true);
			form_selectable_cell(
				'<a class="linkEditMain" href="cereus_ipam_maintenance.php?action=edit&id=' . $row['id'] . '">'
				. html_escape($row['title']) . '</a>',
				$row['id']
			);
			form_selectable_cell(html_escape($row['start_time']), $row['id']);
			form_selectable_cell(html_escape($row['end_time']), $row['id']);
			form_selectable_cell($subnets_display, $row['id']);
			form_selectable_cell($status, $row['id']);
			form_selectable_cell($row['suppress_scans'] ? __('Yes', 'cereus_ipam') : __('No', 'cereus_ipam'), $row['id']);
			form_selectable_cell($row['suppress_alerts'] ? __('Yes', 'cereus_ipam') : __('No', 'cereus_ipam'), $row['id']);
			form_checkbox_cell($row['title'], $row['id']);
			form_end_row();
		}
	} else {
		print '<tr><td colspan="8"><em>' . __('No maintenance windows found. Click the + to add one.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box(false);
	print $nav;
	draw_actions_dropdown($actions);
}
