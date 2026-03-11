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
 | Cereus IPAM - Multi-Tenancy Management UI (Enterprise)                  |
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
if (!cereus_ipam_license_has_multitenancy()) {
	raise_message('cereus_ipam_license', __('Multi-Tenancy requires an Enterprise license.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
	header('Location: cereus_ipam.php');
	exit;
}

$actions = array(
	1 => __('Delete', 'cereus_ipam'),
);

$action = get_nfilter_request_var('action', '');

switch ($action) {
	case 'save':
		cereus_ipam_tenant_save();
		break;
	case 'actions':
		cereus_ipam_tenant_actions();
		break;
	case 'edit':
		top_header();
		cereus_ipam_tenant_edit();
		bottom_footer();
		break;
	default:
		top_header();
		cereus_ipam_tenant_list();
		bottom_footer();
		break;
}

/* ==================== Save ==================== */

function cereus_ipam_tenant_save() {
	if (!isset_request_var('save_component')) {
		return;
	}

	$id          = get_filter_request_var('id');
	$name        = cereus_ipam_sanitize_text(get_nfilter_request_var('name', ''), 255);
	$description = cereus_ipam_sanitize_text(get_nfilter_request_var('description', ''), 65535);
	$enabled     = isset_request_var('enabled') ? 1 : 0;

	/* Validate name */
	if (empty($name)) {
		raise_message('cereus_ipam_name', __('Tenant name is required.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_tenants.php?action=edit&id=' . $id);
		exit;
	}

	/* Check unique name */
	$existing = db_fetch_cell_prepared(
		"SELECT id FROM plugin_cereus_ipam_tenants WHERE name = ? AND id != ?",
		array($name, ($id > 0 ? $id : 0))
	);
	if (!empty($existing)) {
		raise_message('cereus_ipam_dup', __('A tenant with this name already exists.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_tenants.php?action=edit&id=' . $id);
		exit;
	}

	if ($id > 0) {
		$old = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_tenants WHERE id = ?", array($id));
		db_execute_prepared("UPDATE plugin_cereus_ipam_tenants SET
			name = ?, description = ?, enabled = ?
			WHERE id = ?",
			array($name, $description, $enabled, $id));
		cereus_ipam_changelog_record('update', 'setting', $id, $old, array('name' => $name, 'type' => 'tenant'));
		$new_id = $id;
	} else {
		db_execute_prepared("INSERT INTO plugin_cereus_ipam_tenants
			(name, description, enabled)
			VALUES (?, ?, ?)",
			array($name, $description, $enabled));
		$new_id = db_fetch_insert_id();
		cereus_ipam_changelog_record('create', 'setting', $new_id, null, array('name' => $name, 'type' => 'tenant'));
	}

	/* Save member associations */
	if ($new_id > 0) {
		db_execute_prepared("DELETE FROM plugin_cereus_ipam_tenant_members WHERE tenant_id = ?", array($new_id));

		$users = db_fetch_assoc("SELECT id FROM user_auth ORDER BY id");
		foreach ($users as $u) {
			if (isset_request_var('member_user_' . $u['id'])) {
				db_execute_prepared("INSERT INTO plugin_cereus_ipam_tenant_members (tenant_id, user_id) VALUES (?, ?)",
					array($new_id, $u['id']));
			}
		}
	}

	raise_message('cereus_ipam_saved', __('Tenant saved.', 'cereus_ipam'), MESSAGE_LEVEL_INFO);
	header('Location: cereus_ipam_tenants.php');
	exit;
}

/* ==================== Bulk Actions ==================== */

function cereus_ipam_tenant_actions() {
	global $actions;

	if (isset_request_var('selected_items')) {
		$selected_items = sanitize_unserialize_selected_items(get_nfilter_request_var('selected_items'));

		if ($selected_items !== false) {
			$drp_action = get_nfilter_request_var('drp_action');

			foreach ($selected_items as $id) {
				if (!is_numeric($id) || $id <= 0) continue;

				switch ($drp_action) {
					case '1': /* delete */
						$old = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_tenants WHERE id = ?", array($id));
						/* Remove member associations */
						db_execute_prepared("DELETE FROM plugin_cereus_ipam_tenant_members WHERE tenant_id = ?", array($id));
						/* Unlink sections from this tenant */
						db_execute_prepared("UPDATE plugin_cereus_ipam_sections SET tenant_id = NULL WHERE tenant_id = ?", array($id));
						/* Delete the tenant */
						db_execute_prepared("DELETE FROM plugin_cereus_ipam_tenants WHERE id = ?", array($id));
						if (cacti_sizeof($old)) {
							cereus_ipam_changelog_record('delete', 'setting', $id, $old, array('type' => 'tenant'));
						}
						break;
				}
			}
		}

		header('Location: cereus_ipam_tenants.php');
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
	form_start('cereus_ipam_tenants.php');
	html_start_box($actions[get_nfilter_request_var('drp_action')], '60%', '', '3', 'center', '');

	if (cacti_sizeof($item_array)) {
		foreach ($item_array as $id) {
			$row = db_fetch_row_prepared('SELECT name FROM plugin_cereus_ipam_tenants WHERE id = ?', array($id));
			if (cacti_sizeof($row)) {
				print '<tr><td class="odd"><span class="deleteMarker">' . html_escape($row['name']) . '</span></td></tr>';
			}
		}
	}

	print '<tr><td class="saveRow"><p>' . __('Are you sure you want to delete the selected tenant(s)? Sections will be unlinked and set to global.', 'cereus_ipam') . '</p></td></tr>';

	$save_html = "<input type='button' class='ui-button ui-corner-all ui-widget' value='" . __esc('Cancel', 'cereus_ipam') . "' onClick='cactiReturnTo(\"cereus_ipam_tenants.php\")'>&nbsp;";
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

function cereus_ipam_tenant_edit() {
	$id = get_filter_request_var('id');

	if ($id > 0) {
		$tenant = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_tenants WHERE id = ?", array($id));
		if (!cacti_sizeof($tenant)) {
			raise_message('cereus_ipam_nf', __('Tenant not found.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
			header('Location: cereus_ipam_tenants.php');
			exit;
		}
		$header = __('Edit Tenant: %s', html_escape($tenant['name']), 'cereus_ipam');
	} else {
		$tenant = array();
		$header = __('New Tenant', 'cereus_ipam');
	}

	$fields = array(
		'tenant_header' => array(
			'friendly_name' => __('Tenant Settings', 'cereus_ipam'),
			'method'        => 'spacer',
		),
		'name' => array(
			'friendly_name' => __('Name', 'cereus_ipam'),
			'description'   => __('A unique name for this tenant.', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => $tenant['name'] ?? '',
			'max_length'    => 255,
			'size'          => 60,
		),
		'description' => array(
			'friendly_name' => __('Description', 'cereus_ipam'),
			'description'   => __('Optional description of this tenant.', 'cereus_ipam'),
			'method'        => 'textarea',
			'value'         => $tenant['description'] ?? '',
			'textarea_rows' => 3,
			'textarea_cols' => 60,
			'max_length'    => 65535,
		),
		'enabled' => array(
			'friendly_name' => __('Enabled', 'cereus_ipam'),
			'description'   => __('When checked, this tenant is active and can be assigned to sections.', 'cereus_ipam'),
			'method'        => 'checkbox',
			'value'         => $tenant['enabled'] ?? '1',
			'default'       => 'on',
		),
	);

	form_start('cereus_ipam_tenants.php');
	html_start_box($header, '100%', '', '3', 'center', '');
	draw_edit_form(array(
		'config' => array('no_form_tag' => true),
		'fields' => $fields,
	));
	html_end_box();

	/* Member assignment */
	$current_members = array();
	if ($id > 0) {
		$rows = db_fetch_assoc_prepared("SELECT user_id FROM plugin_cereus_ipam_tenant_members WHERE tenant_id = ?", array($id));
		foreach ($rows as $r) {
			$current_members[$r['user_id']] = true;
		}
	}

	$all_users = db_fetch_assoc("SELECT id, username, full_name FROM user_auth ORDER BY username");

	html_start_box(__('Member Users', 'cereus_ipam'), '100%', '', '3', 'center', '');

	if (cacti_sizeof($all_users)) {
		$display_text = array(
			array('display' => __('Username', 'cereus_ipam'), 'align' => 'left'),
			array('display' => __('Full Name', 'cereus_ipam'), 'align' => 'left'),
			array('display' => __('Member', 'cereus_ipam'), 'align' => 'center'),
		);
		html_header($display_text);

		foreach ($all_users as $u) {
			$checked = isset($current_members[$u['id']]) ? ' checked' : '';
			form_alternate_row('user_' . $u['id']);
			print '<td>' . html_escape($u['username']) . '</td>';
			print '<td>' . html_escape($u['full_name'] ?? '') . '</td>';
			print '<td class="center"><input type="checkbox" name="member_user_' . $u['id'] . '" value="on"' . $checked . '></td>';
			form_end_row();
		}
	} else {
		print '<tr><td colspan="3"><em>' . __('No Cacti users found.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box();

	/* Show linked sections for existing tenants */
	if ($id > 0) {
		$linked_sections = db_fetch_assoc_prepared(
			"SELECT s.id, s.name, s.description,
				(SELECT COUNT(*) FROM plugin_cereus_ipam_subnets WHERE section_id = s.id) AS subnet_count
			FROM plugin_cereus_ipam_sections s
			WHERE s.tenant_id = ?
			ORDER BY s.name",
			array($id)
		);

		html_start_box(__('Linked Sections', 'cereus_ipam'), '100%', '', '3', 'center', '');
		if (cacti_sizeof($linked_sections)) {
			$display_text = array(
				array('display' => __('Section', 'cereus_ipam'),     'align' => 'left'),
				array('display' => __('Description', 'cereus_ipam'), 'align' => 'left'),
				array('display' => __('Subnets', 'cereus_ipam'),     'align' => 'center'),
			);
			html_header($display_text);

			foreach ($linked_sections as $ls) {
				form_alternate_row('ls_' . $ls['id']);
				form_selectable_cell(
					'<a href="cereus_ipam.php?action=section_edit&id=' . $ls['id'] . '">' . html_escape($ls['name']) . '</a>',
					$ls['id']
				);
				form_selectable_cell(html_escape($ls['description'] ?? ''), $ls['id']);
				$scount = (int) $ls['subnet_count'];
				if ($scount > 0) {
					form_selectable_cell('<a href="cereus_ipam.php?section_id=' . $ls['id'] . '">' . $scount . '</a>', $ls['id'], '', 'text-align:center;');
				} else {
					form_selectable_cell('0', $ls['id'], '', 'text-align:center;');
				}
				form_end_row();
			}
		} else {
			print '<tr><td colspan="3"><em>' . __('No sections linked to this tenant.', 'cereus_ipam') . '</em></td></tr>';
		}
		html_end_box();
	}

	form_hidden_box('id', $id, '0');
	form_hidden_box('save_component', '1', '');
	form_save_button('cereus_ipam_tenants.php', 'return');
}

/* ==================== List View ==================== */

function cereus_ipam_tenant_list() {
	global $actions;

	/* Filter handling */
	if (isset_request_var('clear')) {
		kill_session_var('sess_cipam_tenant_filter');
		kill_session_var('sess_cipam_tenant_rows');
		kill_session_var('sess_cipam_tenant_page');
		unset_request_var('filter');
		unset_request_var('rows');
		unset_request_var('page');
	}

	load_current_session_value('filter', 'sess_cipam_tenant_filter', '');
	load_current_session_value('rows',   'sess_cipam_tenant_rows',   '-1');
	load_current_session_value('page',   'sess_cipam_tenant_page',   '1');

	$filter = get_request_var('filter');
	$rows   = get_request_var('rows');
	$page   = get_request_var('page');

	if ($rows == -1) {
		$rows = read_config_option('num_rows_table');
	}
	$rows = max(1, (int) $rows);
	$page = max(1, (int) $page);

	/* Filter bar */
	html_start_box(__('Tenants', 'cereus_ipam'), '100%', '', '3', 'center', 'cereus_ipam_tenants.php?action=edit&id=0');
	?>
	<tr class='even'>
		<td>
			<form id='form_cipam_tenant' action='cereus_ipam_tenants.php'>
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
				loadPageNoHeader('cereus_ipam_tenants.php?header=false&filter=' + encodeURIComponent($('#filter').val()));
			}
			$(function() {
				$('#refresh').click(function() { applyFilter(); });
				$('#clear').click(function() { loadPageNoHeader('cereus_ipam_tenants.php?header=false&clear=1'); });
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
		$sql_where .= ' AND (t.name LIKE ? OR t.description LIKE ?)';
		$sql_params[] = '%' . $safe . '%';
		$sql_params[] = '%' . $safe . '%';
	}

	$total_rows = db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_tenants t $sql_where", $sql_params);

	$tenants = db_fetch_assoc_prepared(
		"SELECT t.*,
			(SELECT COUNT(*) FROM plugin_cereus_ipam_tenant_members WHERE tenant_id = t.id) AS member_count,
			(SELECT COUNT(*) FROM plugin_cereus_ipam_sections WHERE tenant_id = t.id) AS section_count
		FROM plugin_cereus_ipam_tenants t
		$sql_where
		ORDER BY t.name
		LIMIT " . (($page - 1) * $rows) . ", $rows",
		$sql_params
	);

	$nav = html_nav_bar('cereus_ipam_tenants.php', MAX_DISPLAY_PAGES, $page, $rows, $total_rows, 6, __('Tenants', 'cereus_ipam'));
	print $nav;

	form_start('cereus_ipam_tenants.php', 'chk');
	html_start_box('', '100%', '', '3', 'center', '');

	$display_text = array(
		'name'          => array('display' => __('Name', 'cereus_ipam'),        'sort' => 'ASC'),
		'description'   => array('display' => __('Description', 'cereus_ipam'), 'sort' => 'ASC'),
		'member_count'  => array('display' => __('Members', 'cereus_ipam')),
		'section_count' => array('display' => __('Sections', 'cereus_ipam')),
		'nosort_enabled' => array('display' => __('Enabled', 'cereus_ipam')),
	);

	html_header_sort_checkbox($display_text, get_request_var('sort_column', 'name'), get_request_var('sort_direction', 'ASC'));

	if (cacti_sizeof($tenants)) {
		foreach ($tenants as $row) {
			form_alternate_row('line' . $row['id'], true);
			form_selectable_cell(
				'<a class="linkEditMain" href="cereus_ipam_tenants.php?action=edit&id=' . $row['id'] . '">'
				. html_escape($row['name']) . '</a>',
				$row['id']
			);
			form_selectable_cell(html_escape($row['description'] ?? ''), $row['id']);
			form_selectable_cell($row['member_count'], $row['id']);
			form_selectable_cell($row['section_count'], $row['id']);
			form_selectable_cell($row['enabled'] ? __('Yes', 'cereus_ipam') : __('No', 'cereus_ipam'), $row['id']);
			form_checkbox_cell($row['name'], $row['id']);
			form_end_row();
		}
	} else {
		print '<tr><td colspan="6"><em>' . __('No tenants found. Click the + to add one.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box(false);
	print $nav;
	draw_actions_dropdown($actions);
}
