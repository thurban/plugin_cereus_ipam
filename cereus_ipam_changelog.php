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
 | Cereus IPAM - Audit Log Viewer                                          |
 +-------------------------------------------------------------------------+
*/

chdir('../../');
include('./include/auth.php');
include_once('./plugins/cereus_ipam/includes/constants.php');
include_once('./plugins/cereus_ipam/lib/license_check.php');
include_once('./plugins/cereus_ipam/lib/changelog.php');

$action = get_nfilter_request_var('action', '');

switch ($action) {
	case 'csv_export':
		cereus_ipam_changelog_csv();
		break;
	case 'purge':
		db_execute("TRUNCATE TABLE plugin_cereus_ipam_changelog");
		if (isset_request_var('header') && get_nfilter_request_var('header') == 'false') {
			cereus_ipam_changelog_list();
			print "<script type='text/javascript'>$(function(){ raiseMessage('" . __esc('IPAM Changelog', 'cereus_ipam') . "', '', '" . __esc('Changelog purged.', 'cereus_ipam') . "', MESSAGE_LEVEL_INFO); });</script>\n";
			exit;
		}
		raise_message('cereus_ipam_purged', __('Changelog purged.', 'cereus_ipam'), MESSAGE_LEVEL_INFO);
		header('Location: cereus_ipam_changelog.php');
		exit;
	default:
		top_header();
		cereus_ipam_changelog_list();
		bottom_footer();
		break;
}

/* ==================== Log List ==================== */

function cereus_ipam_changelog_list() {
	/* Filter handling */
	if (isset_request_var('clear')) {
		kill_session_var('sess_cipam_log_filter');
		kill_session_var('sess_cipam_log_type');
		kill_session_var('sess_cipam_log_action');
		kill_session_var('sess_cipam_log_rows');
		kill_session_var('sess_cipam_log_page');
		unset_request_var('filter');
		unset_request_var('object_type');
		unset_request_var('log_action');
		unset_request_var('rows');
		unset_request_var('page');
	}

	load_current_session_value('filter',      'sess_cipam_log_filter', '');
	load_current_session_value('object_type', 'sess_cipam_log_type',   '-1');
	load_current_session_value('log_action',  'sess_cipam_log_action', '-1');
	load_current_session_value('rows',        'sess_cipam_log_rows',   '-1');
	load_current_session_value('page',        'sess_cipam_log_page',   '1');

	$filter      = get_request_var('filter');
	$object_type = get_request_var('object_type');
	$log_action  = get_request_var('log_action');
	$rows        = get_request_var('rows');
	$page        = get_request_var('page');

	if ($rows == -1) {
		$rows = read_config_option('num_rows_table');
	}
	$rows = max(1, (int) $rows);
	$page = max(1, (int) $page);

	/* Filter bar */
	html_start_box(__('IPAM Changelog', 'cereus_ipam'), '100%', '', '3', 'center', '');
	?>
	<tr class='even noprint'>
		<td>
			<form id='form_cipam_log' action='cereus_ipam_changelog.php'>
				<table class='filterTable'>
					<tr>
						<td><?php print __('Search', 'cereus_ipam'); ?></td>
						<td><input type='text' class='ui-state-default ui-corner-all' id='filter' size='25' value='<?php print html_escape($filter); ?>'></td>
						<td><?php print __('Type', 'cereus_ipam'); ?></td>
						<td>
							<select id='object_type'>
								<option value='-1' <?php print ($object_type == '-1' ? 'selected' : ''); ?>><?php print __('All', 'cereus_ipam'); ?></option>
								<option value='section' <?php print ($object_type == 'section' ? 'selected' : ''); ?>><?php print __('Section', 'cereus_ipam'); ?></option>
								<option value='subnet' <?php print ($object_type == 'subnet' ? 'selected' : ''); ?>><?php print __('Subnet', 'cereus_ipam'); ?></option>
								<option value='address' <?php print ($object_type == 'address' ? 'selected' : ''); ?>><?php print __('Address', 'cereus_ipam'); ?></option>
								<option value='vlan' <?php print ($object_type == 'vlan' ? 'selected' : ''); ?>><?php print __('VLAN', 'cereus_ipam'); ?></option>
								<option value='vrf' <?php print ($object_type == 'vrf' ? 'selected' : ''); ?>><?php print __('VRF', 'cereus_ipam'); ?></option>
							</select>
						</td>
						<td><?php print __('Action', 'cereus_ipam'); ?></td>
						<td>
							<select id='log_action'>
								<option value='-1' <?php print ($log_action == '-1' ? 'selected' : ''); ?>><?php print __('All', 'cereus_ipam'); ?></option>
								<option value='create' <?php print ($log_action == 'create' ? 'selected' : ''); ?>><?php print __('Create', 'cereus_ipam'); ?></option>
								<option value='update' <?php print ($log_action == 'update' ? 'selected' : ''); ?>><?php print __('Update', 'cereus_ipam'); ?></option>
								<option value='delete' <?php print ($log_action == 'delete' ? 'selected' : ''); ?>><?php print __('Delete', 'cereus_ipam'); ?></option>
								<option value='import' <?php print ($log_action == 'import' ? 'selected' : ''); ?>><?php print __('Import', 'cereus_ipam'); ?></option>
								<option value='scan' <?php print ($log_action == 'scan' ? 'selected' : ''); ?>><?php print __('Scan', 'cereus_ipam'); ?></option>
							</select>
						</td>
						<td>
							<span>
								<input type='button' class='ui-button' id='go' value='<?php print __esc('Go', 'cereus_ipam'); ?>'>
								<input type='button' class='ui-button' id='clear' value='<?php print __esc('Clear', 'cereus_ipam'); ?>'>
								<input type='button' class='ui-button' id='csv' value='<?php print __esc('CSV Export', 'cereus_ipam'); ?>'>
								<input type='button' class='ui-button' id='purge' value='<?php print __esc('Purge', 'cereus_ipam'); ?>'>
							</span>
						</td>
					</tr>
				</table>
			</form>
			<script type='text/javascript'>
			function applyFilter() {
				var url = 'cereus_ipam_changelog.php?header=false'
					+ '&filter=' + encodeURIComponent($('#filter').val())
					+ '&object_type=' + $('#object_type').val()
					+ '&log_action=' + $('#log_action').val();
				loadPageNoHeader(url);
			}
			function purgeLog() {
				var $dlg = $('<div style="display:none"><h4><?php print __esc('Confirm Purge', 'cereus_ipam'); ?></h4><p><?php print __esc('Are you sure you want to purge the entire changelog?', 'cereus_ipam'); ?></p></div>');
				$('body').append($dlg);
				$dlg.dialog({
					title: '<?php print __esc('Purge Changelog', 'cereus_ipam'); ?>',
					draggable: true, resizable: false, height: 'auto', minWidth: 400, modal: true,
					buttons: {
						'<?php print __esc('Cancel', 'cereus_ipam'); ?>': function() { $(this).dialog('close'); $dlg.remove(); },
						'<?php print __esc('Purge', 'cereus_ipam'); ?>': function() { $(this).dialog('close'); $dlg.remove(); loadPageNoHeader('cereus_ipam_changelog.php?header=false&action=purge'); }
					}
				});
			}
			$(function() {
				$('#go').click(function() { applyFilter(); });
				$('#clear').click(function() { loadPageNoHeader('cereus_ipam_changelog.php?header=false&clear=1'); });
				$('#csv').click(function() { document.location = 'cereus_ipam_changelog.php?action=csv_export&filter=' + encodeURIComponent($('#filter').val()) + '&object_type=' + $('#object_type').val() + '&log_action=' + $('#log_action').val(); });
				$('#purge').click(function() { purgeLog(); });
				$('#object_type, #log_action').change(function() { applyFilter(); });
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
		$sql_where .= ' AND (c.ip_address LIKE ?)';
		$sql_params[] = '%' . $safe . '%';
	}

	if ($object_type != '-1') {
		$sql_where .= ' AND c.object_type = ?';
		$sql_params[] = $object_type;
	}

	if ($log_action != '-1') {
		$sql_where .= ' AND c.action = ?';
		$sql_params[] = $log_action;
	}

	$total_rows = db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_changelog c $sql_where", $sql_params);

	$logs = db_fetch_assoc_prepared(
		"SELECT c.*, u.username
		FROM plugin_cereus_ipam_changelog c
		LEFT JOIN user_auth u ON u.id = c.user_id
		$sql_where
		ORDER BY c.created DESC
		LIMIT " . (($page - 1) * $rows) . ", $rows",
		$sql_params
	);

	$nav = html_nav_bar('cereus_ipam_changelog.php', MAX_DISPLAY_PAGES, $page, $rows, $total_rows, 7, __('Entries', 'cereus_ipam'));
	print $nav;

	html_start_box('', '100%', '', '3', 'center', '');

	$display_text = array(
		'created'     => array('display' => __('Date', 'cereus_ipam'),       'sort' => 'DESC'),
		'username'    => array('display' => __('User', 'cereus_ipam'),       'sort' => 'ASC'),
		'action'      => array('display' => __('Action', 'cereus_ipam'),     'sort' => 'ASC'),
		'object_type' => array('display' => __('Type', 'cereus_ipam'),       'sort' => 'ASC'),
		'object_id'   => array('display' => __('Object ID', 'cereus_ipam'), 'sort' => 'ASC'),
		'nosort1'     => array('display' => __('Details', 'cereus_ipam')),
		'ip_address'  => array('display' => __('Client IP', 'cereus_ipam'), 'sort' => 'ASC'),
	);

	html_header_sort($display_text, get_request_var('sort_column', 'created'), get_request_var('sort_direction', 'DESC'));

	if (cacti_sizeof($logs)) {
		foreach ($logs as $log) {
			form_alternate_row('log_' . $log['id']);

			form_selectable_cell($log['created'], $log['id']);
			form_selectable_cell(html_escape($log['username'] ?? __('System', 'cereus_ipam')), $log['id']);

			/* Color-coded action */
			$action_colors = array(
				'create' => '#4CAF50',
				'update' => '#2196F3',
				'delete' => '#F44336',
				'import' => '#9C27B0',
				'scan'   => '#FF9800',
			);
			$color = $action_colors[$log['action']] ?? '#9E9E9E';
			form_selectable_cell('<span style="color:' . $color . ';">' . html_escape(ucfirst($log['action'])) . '</span>', $log['id']);

			form_selectable_cell(html_escape(ucfirst($log['object_type'])), $log['id']);
			form_selectable_cell($log['object_id'], $log['id']);

			/* Build details from new_value JSON */
			$details = '';
			if (!empty($log['new_value'])) {
				$data = json_decode($log['new_value'], true);
				if (is_array($data)) {
					$parts = array();
					foreach ($data as $k => $v) {
						if (is_scalar($v)) {
							$parts[] = $k . '=' . $v;
						}
					}
					$details = implode(', ', array_slice($parts, 0, 5));
				}
			}
			form_selectable_cell(html_escape($details), $log['id']);
			form_selectable_cell(html_escape($log['ip_address'] ?? ''), $log['id']);

			form_end_row();
		}
	} else {
		print "<tr><td colspan='7'><em>" . __('No changelog entries found.', 'cereus_ipam') . "</em></td></tr>\n";
	}

	html_end_box();
	print $nav;
}

/* ==================== CSV Export ==================== */

function cereus_ipam_changelog_csv() {
	$filter      = get_nfilter_request_var('filter', '');
	$object_type = get_nfilter_request_var('object_type', '-1');
	$log_action  = get_nfilter_request_var('log_action', '-1');

	$sql_where  = 'WHERE 1=1';
	$sql_params = array();

	if (!empty($filter)) {
		$safe = str_replace(array('%', '_'), array('\\%', '\\_'), $filter);
		$sql_where .= ' AND (c.ip_address LIKE ?)';
		$sql_params[] = '%' . $safe . '%';
	}
	if ($object_type != '-1') {
		$sql_where .= ' AND c.object_type = ?';
		$sql_params[] = $object_type;
	}
	if ($log_action != '-1') {
		$sql_where .= ' AND c.action = ?';
		$sql_params[] = $log_action;
	}

	$logs = db_fetch_assoc_prepared(
		"SELECT c.*, u.username
		FROM plugin_cereus_ipam_changelog c
		LEFT JOIN user_auth u ON u.id = c.user_id
		$sql_where ORDER BY c.created DESC LIMIT 10000",
		$sql_params
	);

	header('Content-Type: text/csv; charset=UTF-8');
	header('Content-Disposition: attachment; filename="cereus_ipam_changelog_' . date('Ymd_His') . '.csv"');

	$fh = fopen('php://output', 'w');
	fputcsv($fh, array('Date', 'User', 'Action', 'Object Type', 'Object ID', 'Old Value', 'New Value', 'Client IP'));

	foreach ($logs as $log) {
		fputcsv($fh, array(
			$log['created'],
			$log['username'] ?? 'System',
			$log['action'],
			$log['object_type'],
			$log['object_id'],
			$log['old_value'] ?? '',
			$log['new_value'] ?? '',
			$log['ip_address'] ?? '',
		));
	}

	fclose($fh);
	exit;
}
