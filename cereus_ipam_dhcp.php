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
 | Cereus IPAM - DHCP Scope Management UI (Enterprise)                     |
 +-------------------------------------------------------------------------+
*/

chdir('../../');
include('./include/auth.php');
include_once('./plugins/cereus_ipam/includes/constants.php');
include_once('./plugins/cereus_ipam/lib/license_check.php');
include_once('./plugins/cereus_ipam/lib/validation.php');
include_once('./plugins/cereus_ipam/lib/functions.php');
include_once('./plugins/cereus_ipam/lib/changelog.php');
include_once('./plugins/cereus_ipam/lib/dhcp.php');

/* Enterprise license gate */
if (!cereus_ipam_license_has_dhcp_monitoring()) {
	raise_message('cereus_ipam_license', __('DHCP Scope Monitoring requires an Enterprise license.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
	header('Location: cereus_ipam.php');
	exit;
}

$actions = array(
	1 => __('Delete', 'cereus_ipam'),
);

$action = get_nfilter_request_var('action', '');

switch ($action) {
	case 'save':
		cereus_ipam_dhcp_save();
		break;
	case 'actions':
		cereus_ipam_dhcp_actions();
		break;
	case 'edit':
		top_header();
		cereus_ipam_dhcp_edit();
		bottom_footer();
		break;
	case 'poll':
		cereus_ipam_dhcp_manual_poll();
		break;
	default:
		top_header();
		cereus_ipam_dhcp_list();
		bottom_footer();
		break;
}

/* ==================== Save ==================== */

function cereus_ipam_dhcp_save() {
	if (!isset_request_var('save_component')) {
		return;
	}

	$id             = get_filter_request_var('id', FILTER_VALIDATE_INT);
	$subnet_id      = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);
	$server_host_id = get_filter_request_var('server_host_id', FILTER_VALIDATE_INT);
	$server_ip      = cereus_ipam_sanitize_text(get_nfilter_request_var('server_ip', ''), 45);
	$scope_name     = cereus_ipam_sanitize_text(get_nfilter_request_var('scope_name', ''), 255);
	$oid_active     = cereus_ipam_sanitize_text(get_nfilter_request_var('oid_active', ''), 255);
	$oid_total      = cereus_ipam_sanitize_text(get_nfilter_request_var('oid_total', ''), 255);
	$oid_free       = cereus_ipam_sanitize_text(get_nfilter_request_var('oid_free', ''), 255);
	$poll_interval  = get_filter_request_var('poll_interval', FILTER_VALIDATE_INT);
	$enabled        = isset_request_var('enabled') ? 1 : 0;

	if (empty($id) || $id === false) {
		$id = 0;
	}
	if (empty($subnet_id) || $subnet_id === false) {
		$subnet_id = 0;
	}
	if (empty($server_host_id) || $server_host_id === false) {
		$server_host_id = 0;
	}

	/* Treat 0 or empty server_host_id as NULL */
	if (empty($server_host_id)) {
		$server_host_id = null;
	}

	/* Validate server_ip */
	if (empty($server_ip) || !cereus_ipam_validate_ip($server_ip)) {
		raise_message('cereus_ipam_ip', __('A valid server IP address is required.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_dhcp.php?action=edit&id=' . $id);
		exit;
	}

	/* Validate OIDs are non-empty */
	if (empty($oid_active) || empty($oid_total) || empty($oid_free)) {
		raise_message('cereus_ipam_oid', __('All three OID fields (Active, Total, Free) are required.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_dhcp.php?action=edit&id=' . $id);
		exit;
	}

	/* Validate subnet_id exists */
	if ($subnet_id > 0) {
		$subnet_exists = db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
		if (!$subnet_exists) {
			raise_message('cereus_ipam_subnet', __('Selected subnet does not exist.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
			header('Location: cereus_ipam_dhcp.php?action=edit&id=' . $id);
			exit;
		}
	} else {
		raise_message('cereus_ipam_subnet', __('A subnet must be selected.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_dhcp.php?action=edit&id=' . $id);
		exit;
	}

	/* Validate poll_interval is a positive integer */
	if (empty($poll_interval) || $poll_interval < 1) {
		$poll_interval = 300;
	}

	if ($id > 0) {
		$old = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_dhcp_scopes WHERE id = ?", array($id));

		db_execute_prepared("UPDATE plugin_cereus_ipam_dhcp_scopes SET
			subnet_id = ?, server_host_id = ?, server_ip = ?, scope_name = ?,
			oid_active = ?, oid_total = ?, oid_free = ?,
			poll_interval = ?, enabled = ?
			WHERE id = ?",
			array($subnet_id, $server_host_id, $server_ip, $scope_name,
				$oid_active, $oid_total, $oid_free,
				$poll_interval, $enabled, $id)
		);

		cereus_ipam_changelog_record('update', 'setting', $id, $old, array('scope_name' => $scope_name, 'type' => 'dhcp_scope'));
		$new_id = $id;
	} else {
		db_execute_prepared("INSERT INTO plugin_cereus_ipam_dhcp_scopes
			(subnet_id, server_host_id, server_ip, scope_name,
			 oid_active, oid_total, oid_free, poll_interval, enabled)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			array($subnet_id, $server_host_id, $server_ip, $scope_name,
				$oid_active, $oid_total, $oid_free, $poll_interval, $enabled)
		);

		$new_id = db_fetch_insert_id();
		cereus_ipam_changelog_record('create', 'setting', $new_id, null, array('scope_name' => $scope_name, 'type' => 'dhcp_scope'));
	}

	raise_message('cereus_ipam_saved', __('DHCP scope saved.', 'cereus_ipam'), MESSAGE_LEVEL_INFO);
	header('Location: cereus_ipam_dhcp.php');
	exit;
}

/* ==================== Bulk Actions ==================== */

function cereus_ipam_dhcp_actions() {
	global $actions;

	if (isset_request_var('selected_items')) {
		$selected_items = sanitize_unserialize_selected_items(get_nfilter_request_var('selected_items'));

		if ($selected_items !== false) {
			$drp_action = get_nfilter_request_var('drp_action');

			foreach ($selected_items as $id) {
				if (!is_numeric($id) || $id <= 0) {
					continue;
				}

				switch ($drp_action) {
					case '1':
						$old = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_dhcp_scopes WHERE id = ?", array($id));
						db_execute_prepared("DELETE FROM plugin_cereus_ipam_dhcp_scopes WHERE id = ?", array($id));
						cereus_ipam_changelog_record('delete', 'setting', $id, $old, array('type' => 'dhcp_scope'));
						break;
				}
			}
		}

		header('Location: cereus_ipam_dhcp.php');
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
	form_start('cereus_ipam_dhcp.php');
	html_start_box($actions[get_nfilter_request_var('drp_action')], '60%', '', '3', 'center', '');

	if (cacti_sizeof($item_array)) {
		foreach ($item_array as $id) {
			$row = db_fetch_row_prepared('SELECT scope_name, server_ip FROM plugin_cereus_ipam_dhcp_scopes WHERE id = ?', array($id));
			if (cacti_sizeof($row)) {
				$display = html_escape($row['scope_name']);
				if (empty($display)) {
					$display = html_escape($row['server_ip']);
				}
				print '<tr><td class="odd"><span class="deleteMarker">' . $display . '</span></td></tr>';
			}
		}
	}

	print '<tr><td class="saveRow"><p>' . __('Are you sure you want to delete the selected DHCP scope(s)?', 'cereus_ipam') . '</p></td></tr>';

	$save_html = "<input type='button' class='ui-button ui-corner-all ui-widget' value='" . __esc('Cancel', 'cereus_ipam') . "' onClick='cactiReturnTo(\"cereus_ipam_dhcp.php\")'>&nbsp;";
	$save_html .= "<input type='submit' class='ui-button ui-corner-all ui-widget' value='" . __esc('Continue', 'cereus_ipam') . "'>";
	print "<tr><td class='saveRow'>$save_html</td></tr>";

	html_end_box();
	form_hidden_box('action', 'actions', '');
	form_hidden_box('selected_items', serialize($item_array), '');
	form_hidden_box('drp_action', get_nfilter_request_var('drp_action'), '');
	form_end();
	bottom_footer();
}

/* ==================== Manual Poll ==================== */

function cereus_ipam_dhcp_manual_poll() {
	$id = get_filter_request_var('id');

	if ($id > 0) {
		$result = cereus_ipam_dhcp_poll_scope($id);

		if ($result['success']) {
			raise_message('cereus_ipam_polled', __('DHCP scope polled successfully. Active: %s, Total: %s, Free: %s', $result['active'], $result['total'], $result['free'], 'cereus_ipam'), MESSAGE_LEVEL_INFO);
		} elseif (!empty($result['errors'])) {
			$oid_info = '';
			if (!empty($result['oids'])) {
				$oid_info = ' ' . __('Resolved OIDs: Active=%s, Total=%s, Free=%s.',
					$result['oids']['active'], $result['oids']['total'], $result['oids']['free'], 'cereus_ipam');
			}
			raise_message('cereus_ipam_poll_fail',
				__('DHCP poll returned no valid data.', 'cereus_ipam')
				. ' ' . implode(' | ', $result['errors']) . $oid_info,
				MESSAGE_LEVEL_ERROR
			);
		} else {
			raise_message('cereus_ipam_poll_fail', __('Failed to poll DHCP scope. Check server connectivity and SNMP settings.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		}
	}

	header('Location: cereus_ipam_dhcp.php');
	exit;
}

/* ==================== Edit Form ==================== */

function cereus_ipam_dhcp_edit() {
	$id = get_filter_request_var('id');

	if ($id > 0) {
		$scope = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_dhcp_scopes WHERE id = ?", array($id));
		if (!cacti_sizeof($scope)) {
			raise_message('cereus_ipam_nf', __('DHCP scope not found.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
			header('Location: cereus_ipam_dhcp.php');
			exit;
		}
		$header = __('Edit DHCP Scope: %s', html_escape($scope['scope_name']), 'cereus_ipam');
	} else {
		$scope = array();
		$header = __('New DHCP Scope', 'cereus_ipam');
	}

	/* Build subnet dropdown */
	$subnets_dropdown = cereus_ipam_get_subnets_dropdown();

	/* Build host dropdown */
	$hosts = db_fetch_assoc("SELECT id, description, hostname FROM host ORDER BY description");
	$hosts_dropdown = array(0 => __('None (Direct SNMP)', 'cereus_ipam'));
	if (cacti_sizeof($hosts)) {
		foreach ($hosts as $h) {
			$hosts_dropdown[$h['id']] = html_escape($h['description']) . ' (' . html_escape($h['hostname']) . ')';
		}
	}

	$fields = array(
		'dhcp_header' => array(
			'friendly_name' => __('DHCP Scope Settings', 'cereus_ipam'),
			'method'        => 'spacer',
		),
		'scope_name' => array(
			'friendly_name' => __('Scope Name', 'cereus_ipam'),
			'description'   => __('A descriptive name for this DHCP scope.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $scope['scope_name'] ?? '',
			'max_length'    => 255,
			'size'          => 60,
		),
		'subnet_id' => array(
			'friendly_name' => __('Subnet', 'cereus_ipam'),
			'description'   => __('The IPAM subnet this DHCP scope belongs to.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'value'         => $scope['subnet_id'] ?? 0,
			'array'         => $subnets_dropdown,
		),
		'server_host_id' => array(
			'friendly_name' => __('Cacti Host (SNMP Source)', 'cereus_ipam'),
			'description'   => __('Select a Cacti host to use its SNMP credentials, or choose None for direct SNMP.', 'cereus_ipam'),
			'method'        => 'drop_array',
			'value'         => $scope['server_host_id'] ?? 0,
			'array'         => $hosts_dropdown,
		),
		'server_ip' => array(
			'friendly_name' => __('Server IP', 'cereus_ipam'),
			'description'   => __('The DHCP server IP address for direct SNMP polling (used when no Cacti host is selected).', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $scope['server_ip'] ?? '',
			'max_length'    => 45,
			'size'          => 30,
		),
		'snmp_header' => array(
			'friendly_name' => __('SNMP OID Settings', 'cereus_ipam'),
			'method'        => 'spacer',
		),
		'oid_active' => array(
			'friendly_name' => __('OID - Active Leases', 'cereus_ipam'),
			'description'   => __('SNMP OID for active DHCP leases. For Windows DHCP (Microsoft MIB), the subnet IP is auto-appended as index. E.g. for scope 192.168.1.0 the base OID .1.3.6.1.4.1.311.1.3.2.1.1.2 becomes .1.3.6.1.4.1.311.1.3.2.1.1.2.192.168.1.0 automatically.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $scope['oid_active'] ?? '.1.3.6.1.4.1.311.1.3.2.1.1.2',
			'max_length'    => 255,
			'size'          => 60,
		),
		'oid_total' => array(
			'friendly_name' => __('OID - Total Addresses', 'cereus_ipam'),
			'description'   => __('SNMP OID for total DHCP addresses in scope. For Windows DHCP, the subnet IP index is auto-appended from the linked subnet.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $scope['oid_total'] ?? '.1.3.6.1.4.1.311.1.3.2.1.1.3',
			'max_length'    => 255,
			'size'          => 60,
		),
		'oid_free' => array(
			'friendly_name' => __('OID - Free Addresses', 'cereus_ipam'),
			'description'   => __('SNMP OID for free DHCP addresses in scope. For Windows DHCP, the subnet IP index is auto-appended from the linked subnet.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $scope['oid_free'] ?? '.1.3.6.1.4.1.311.1.3.2.1.1.4',
			'max_length'    => 255,
			'size'          => 60,
		),
		'poll_header' => array(
			'friendly_name' => __('Polling Settings', 'cereus_ipam'),
			'method'        => 'spacer',
		),
		'poll_interval' => array(
			'friendly_name' => __('Poll Interval (seconds)', 'cereus_ipam'),
			'description'   => __('How often to poll this DHCP scope via SNMP, in seconds.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $scope['poll_interval'] ?? 300,
			'max_length'    => 10,
			'size'          => 10,
		),
		'enabled' => array(
			'friendly_name' => __('Enabled', 'cereus_ipam'),
			'description'   => __('Enable or disable polling for this DHCP scope.', 'cereus_ipam'),
			'method'        => 'checkbox',
			'value'         => $scope['enabled'] ?? '1',
			'default'       => 'on',
		),
	);

	form_start('cereus_ipam_dhcp.php');
	html_start_box($header, '100%', '', '3', 'center', '');
	draw_edit_form(array(
		'config' => array('no_form_tag' => true),
		'fields' => $fields,
	));
	html_end_box();

	/* Show current poll results if editing an existing scope */
	if ($id > 0 && cacti_sizeof($scope)) {
		html_start_box(__('Current Poll Results', 'cereus_ipam'), '100%', '', '3', 'center', '');

		$utilization_pct = 0;
		if ($scope['total_leases'] > 0) {
			$utilization_pct = round(($scope['active_leases'] / $scope['total_leases']) * 100, 1);
		}

		print '<tr class="even">';
		print '<td style="padding:8px 15px;">';
		print '<strong>' . __('Active Leases:', 'cereus_ipam') . '</strong> ' . html_escape($scope['active_leases']);
		print ' &nbsp;&nbsp; ';
		print '<strong>' . __('Total Leases:', 'cereus_ipam') . '</strong> ' . html_escape($scope['total_leases']);
		print ' &nbsp;&nbsp; ';
		print '<strong>' . __('Free Leases:', 'cereus_ipam') . '</strong> ' . html_escape($scope['free_leases']);
		print ' &nbsp;&nbsp; ';
		print '<strong>' . __('Utilization:', 'cereus_ipam') . '</strong> ' . cereus_ipam_utilization_bar($utilization_pct);
		print ' &nbsp;&nbsp; ';
		print '<strong>' . __('Last Polled:', 'cereus_ipam') . '</strong> ' . html_escape($scope['last_polled'] ?? __('Never', 'cereus_ipam'));
		print '</td>';
		print '</tr>';

		/* Show resolved OIDs so the user can see what's actually queried */
		$subnet_ip = '';
		if (!empty($scope['subnet_id'])) {
			$subnet_ip = db_fetch_cell_prepared("SELECT subnet FROM plugin_cereus_ipam_subnets WHERE id = ?", array($scope['subnet_id']));
		}
		if (!empty($subnet_ip)) {
			$resolved_active = cereus_ipam_dhcp_resolve_oid($scope['oid_active'], $subnet_ip);
			$resolved_total  = cereus_ipam_dhcp_resolve_oid($scope['oid_total'], $subnet_ip);
			$resolved_free   = cereus_ipam_dhcp_resolve_oid($scope['oid_free'], $subnet_ip);

			if ($resolved_active !== $scope['oid_active'] || $resolved_total !== $scope['oid_total'] || $resolved_free !== $scope['oid_free']) {
				print '<tr class="even">';
				print '<td style="padding:4px 15px; color:#666; font-size:0.9em;">';
				print '<strong>' . __('Resolved OIDs (with subnet index):', 'cereus_ipam') . '</strong><br>';
				print __('Active:', 'cereus_ipam') . ' <code>' . html_escape($resolved_active) . '</code> &nbsp; ';
				print __('Total:', 'cereus_ipam') . ' <code>' . html_escape($resolved_total) . '</code> &nbsp; ';
				print __('Free:', 'cereus_ipam') . ' <code>' . html_escape($resolved_free) . '</code>';
				print '</td>';
				print '</tr>';
			}
		}

		print '<tr class="odd">';
		print '<td style="padding:8px 15px;">';
		print '<a class="ui-button ui-corner-all ui-widget" href="cereus_ipam_dhcp.php?action=poll&id=' . $id . '">' . __('Poll Now', 'cereus_ipam') . '</a>';
		print '</td>';
		print '</tr>';

		html_end_box();
	}

	form_hidden_box('id', $id, '0');
	form_hidden_box('save_component', '1', '');
	form_save_button('cereus_ipam_dhcp.php', 'return');
}

/* ==================== List View ==================== */

function cereus_ipam_dhcp_list() {
	global $actions;

	/* Filter handling */
	if (isset_request_var('clear')) {
		kill_session_var('sess_cipam_dhcp_filter');
		kill_session_var('sess_cipam_dhcp_rows');
		kill_session_var('sess_cipam_dhcp_page');
		kill_session_var('sess_cipam_dhcp_sort_column');
		kill_session_var('sess_cipam_dhcp_sort_direction');
		unset_request_var('filter');
		unset_request_var('rows');
		unset_request_var('page');
		unset_request_var('sort_column');
		unset_request_var('sort_direction');
	}

	load_current_session_value('filter',         'sess_cipam_dhcp_filter',         '');
	load_current_session_value('rows',           'sess_cipam_dhcp_rows',           '-1');
	load_current_session_value('page',           'sess_cipam_dhcp_page',           '1');
	load_current_session_value('sort_column',    'sess_cipam_dhcp_sort_column',    'scope_name');
	load_current_session_value('sort_direction', 'sess_cipam_dhcp_sort_direction', 'ASC');

	$filter         = get_request_var('filter');
	$rows           = get_request_var('rows');
	$page           = get_request_var('page');
	$sort_column    = get_request_var('sort_column');
	$sort_direction = get_request_var('sort_direction');

	if ($rows == -1) {
		$rows = read_config_option('num_rows_table');
	}
	$rows = max(1, (int) $rows);
	$page = max(1, (int) $page);

	/* Filter bar */
	html_start_box(__('DHCP Scopes', 'cereus_ipam'), '100%', '', '3', 'center', 'cereus_ipam_dhcp.php?action=edit&id=0');
	?>
	<tr class='even'>
		<td>
			<form id='form_cipam_dhcp' action='cereus_ipam_dhcp.php'>
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
				loadPageNoHeader('cereus_ipam_dhcp.php?header=false&filter=' + encodeURIComponent($('#filter').val()));
			}
			$(function() {
				$('#refresh').click(function() { applyFilter(); });
				$('#clear').click(function() { loadPageNoHeader('cereus_ipam_dhcp.php?header=false&clear=1'); });
				$('#filter').keypress(function(e) { if (e.which == 13) { applyFilter(); e.preventDefault(); } });
			});
			</script>
		</td>
	</tr>
	<?php
	html_end_box();

	/* Fetch data */
	$total_rows = cereus_ipam_dhcp_get_scope_count($filter);
	$scopes     = cereus_ipam_dhcp_get_all_scopes($filter, $rows, $page, $sort_column, $sort_direction);

	$nav = html_nav_bar('cereus_ipam_dhcp.php', MAX_DISPLAY_PAGES, $page, $rows, $total_rows, 11, __('DHCP Scopes', 'cereus_ipam'));
	print $nav;

	form_start('cereus_ipam_dhcp.php', 'chk');
	html_start_box('', '100%', '', '3', 'center', '');

	$display_text = array(
		'scope_name'     => array('display' => __('Scope Name', 'cereus_ipam'),    'sort' => 'ASC'),
		'nosort_subnet'  => array('display' => __('Subnet', 'cereus_ipam')),
		'nosort_server'  => array('display' => __('Server', 'cereus_ipam')),
		'active_leases'  => array('display' => __('Active', 'cereus_ipam'),        'sort' => 'DESC',  'align' => 'right'),
		'total_leases'   => array('display' => __('Total', 'cereus_ipam'),         'sort' => 'DESC',  'align' => 'right'),
		'free_leases'    => array('display' => __('Free', 'cereus_ipam'),          'sort' => 'DESC',  'align' => 'right'),
		'nosort_util'    => array('display' => __('Utilization', 'cereus_ipam'),    'align' => 'left'),
		'last_polled'    => array('display' => __('Last Polled', 'cereus_ipam'),   'sort' => 'DESC'),
		'enabled'        => array('display' => __('Enabled', 'cereus_ipam'),       'sort' => 'ASC',   'align' => 'center'),
		'nosort_actions' => array('display' => __('Actions', 'cereus_ipam'),        'align' => 'center'),
	);

	html_header_sort_checkbox($display_text, $sort_column, $sort_direction);

	if (cacti_sizeof($scopes)) {
		foreach ($scopes as $row) {
			$utilization_pct = 0;
			if ($row['total_leases'] > 0) {
				$utilization_pct = round(($row['active_leases'] / $row['total_leases']) * 100, 1);
			}

			/* Subnet display */
			$subnet_display = '';
			if (!empty($row['subnet'])) {
				$subnet_display = html_escape($row['subnet'] . '/' . $row['mask']);
				if (!empty($row['subnet_desc'])) {
					$subnet_display .= ' - ' . html_escape($row['subnet_desc']);
				}
			}

			/* Server display */
			$server_display = html_escape($row['server_ip']);
			if (!empty($row['host_desc'])) {
				$server_display = html_escape($row['host_desc']) . ' (' . $server_display . ')';
			}

			/* Scope name with edit link */
			$scope_display = !empty($row['scope_name']) ? html_escape($row['scope_name']) : html_escape($row['server_ip']);

			form_alternate_row('line' . $row['id'], true);

			form_selectable_cell(
				'<a class="linkEditMain" href="cereus_ipam_dhcp.php?action=edit&id=' . $row['id'] . '">'
				. $scope_display . '</a>',
				$row['id']
			);
			form_selectable_cell($subnet_display, $row['id']);
			form_selectable_cell($server_display, $row['id']);
			form_selectable_cell(number_format_i18n($row['active_leases']), $row['id'], '', 'right');
			form_selectable_cell(number_format_i18n($row['total_leases']), $row['id'], '', 'right');
			form_selectable_cell(number_format_i18n($row['free_leases']), $row['id'], '', 'right');
			form_selectable_cell(cereus_ipam_utilization_bar($utilization_pct), $row['id']);
			form_selectable_cell(html_escape($row['last_polled'] ?? __('Never', 'cereus_ipam')), $row['id']);
			form_selectable_cell($row['enabled'] ? __('Yes', 'cereus_ipam') : __('No', 'cereus_ipam'), $row['id'], '', 'center');
			form_selectable_cell(
				'<a class="pic" href="cereus_ipam_dhcp.php?action=poll&id=' . $row['id'] . '" title="' . __esc('Poll Now', 'cereus_ipam') . '"><i class="fas fa-sync-alt"></i></a>',
				$row['id'], '', 'center'
			);
			form_checkbox_cell($scope_display, $row['id']);
			form_end_row();
		}
	} else {
		print '<tr><td colspan="11"><em>' . __('No DHCP scopes found. Click the + to add one.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box(false);
	print $nav;
	draw_actions_dropdown($actions);
}
