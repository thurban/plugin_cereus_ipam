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
 | Cereus IPAM - Global Search Page                                        |
 +-------------------------------------------------------------------------+
*/

chdir('../../');
include('./include/auth.php');
include_once('./plugins/cereus_ipam/includes/constants.php');
include_once('./plugins/cereus_ipam/lib/license_check.php');
include_once('./plugins/cereus_ipam/lib/validation.php');
include_once('./plugins/cereus_ipam/lib/ip_utils.php');
include_once('./plugins/cereus_ipam/lib/functions.php');

top_header();
cereus_ipam_search();
bottom_footer();

/* ==================== Global Search ==================== */

function cereus_ipam_search() {
	global $config;

	$query     = get_nfilter_request_var('query', '');
	$use_regex = get_nfilter_request_var('use_regex', '');

	/* Search box */
	html_start_box(__('IPAM Global Search', 'cereus_ipam'), '100%', '', '3', 'center', '');
	?>
	<tr class='even'>
		<td>
			<form id='form_cipam_search' method='get' action='cereus_ipam_search.php'>
				<table class='filterTable'>
					<tr>
						<td><?php print __('Search', 'cereus_ipam'); ?></td>
						<td>
							<input type='text' class='ui-state-default ui-corner-all' id='query' name='query'
								value='<?php print html_escape($query); ?>' size='60'
								placeholder='<?php print __esc('IP, hostname, MAC, subnet, VLAN, VRF, section...', 'cereus_ipam'); ?>'>
						</td>
						<?php if (cereus_ipam_license_has_advanced_search()) { ?>
						<td>
							<label><input type='checkbox' id='use_regex' name='use_regex' value='on' <?php print ($use_regex == 'on' ? 'checked' : ''); ?>> <?php print __('Regex', 'cereus_ipam'); ?></label>
						</td>
						<?php } ?>
						<td>
							<input type='submit' class='ui-button' value='<?php print __esc('Search', 'cereus_ipam'); ?>'>
							<input type='button' class='ui-button' id='clear_search' value='<?php print __esc('Clear', 'cereus_ipam'); ?>'>
						</td>
					</tr>
				</table>
			</form>
			<script type='text/javascript'>
			$(function() {
				$('#clear_search').click(function() {
					$('#query').val('');
					document.location = 'cereus_ipam_search.php';
				});
				$('#query').focus();
			});
			</script>
		</td>
	</tr>
	<?php
	html_end_box();

	if (empty($query)) {
		return;
	}

	$is_regex = ($use_regex == 'on' && cereus_ipam_license_has_advanced_search());

	/* Search Addresses */
	cereus_ipam_search_addresses($query, $is_regex);

	/* Search Subnets */
	cereus_ipam_search_subnets($query, $is_regex);

	/* Search VLANs (Professional+) */
	if (cereus_ipam_license_has_vlans()) {
		cereus_ipam_search_vlans($query, $is_regex);
	}

	/* Search VRFs (Professional+) */
	if (cereus_ipam_license_has_vrfs()) {
		cereus_ipam_search_vrfs($query, $is_regex);
	}

	/* Search Sections */
	cereus_ipam_search_sections($query, $is_regex);
}

/* ==================== Search: Addresses ==================== */

function cereus_ipam_search_addresses($query, $is_regex) {
	if ($is_regex) {
		$sql = "SELECT a.id, a.ip, a.hostname, a.mac_address, a.description, a.owner, a.state, a.subnet_id,
					s.subnet, s.mask
				FROM plugin_cereus_ipam_addresses a
				LEFT JOIN plugin_cereus_ipam_subnets s ON s.id = a.subnet_id
				WHERE (a.ip REGEXP ? OR a.hostname REGEXP ? OR a.mac_address REGEXP ?
					OR a.description REGEXP ? OR a.owner REGEXP ?)
				ORDER BY INET_ATON(a.ip) LIMIT 50";
		$params = array($query, $query, $query, $query, $query);
	} else {
		$safe = '%' . str_replace(array('%', '_'), array('\\%', '\\_'), $query) . '%';
		$sql = "SELECT a.id, a.ip, a.hostname, a.mac_address, a.description, a.owner, a.state, a.subnet_id,
					s.subnet, s.mask
				FROM plugin_cereus_ipam_addresses a
				LEFT JOIN plugin_cereus_ipam_subnets s ON s.id = a.subnet_id
				WHERE (a.ip LIKE ? OR a.hostname LIKE ? OR a.mac_address LIKE ?
					OR a.description LIKE ? OR a.owner LIKE ?)
				ORDER BY INET_ATON(a.ip) LIMIT 50";
		$params = array($safe, $safe, $safe, $safe, $safe);
	}

	$results = db_fetch_assoc_prepared($sql, $params);

	$state_colors = array(
		'active' => '#4CAF50', 'reserved' => '#2196F3', 'dhcp' => '#9C27B0',
		'offline' => '#F44336', 'available' => '#9E9E9E',
	);

	$count = cacti_sizeof($results);
	html_start_box(__('Addresses', 'cereus_ipam') . ' (' . $count . ')', '100%', '', '3', 'center', '');

	if ($count > 0) {
		$display_text = array(
			array('display' => __('IP Address', 'cereus_ipam'), 'align' => 'left'),
			array('display' => __('Hostname', 'cereus_ipam'),   'align' => 'left'),
			array('display' => __('MAC', 'cereus_ipam'),        'align' => 'left'),
			array('display' => __('Owner', 'cereus_ipam'),      'align' => 'left'),
			array('display' => __('State', 'cereus_ipam'),      'align' => 'left'),
			array('display' => __('Subnet', 'cereus_ipam'),     'align' => 'left'),
		);
		html_header($display_text);

		foreach ($results as $row) {
			$color = $state_colors[$row['state']] ?? '#9E9E9E';
			form_alternate_row('addr_' . $row['id']);
			print '<td><a class="linkEditMain" href="cereus_ipam_addresses.php?action=edit&id=' . $row['id'] . '&subnet_id=' . $row['subnet_id'] . '">' . html_escape($row['ip']) . '</a></td>';
			print '<td>' . html_escape($row['hostname'] ?? '') . '</td>';
			print '<td>' . html_escape($row['mac_address'] ?? '') . '</td>';
			print '<td>' . html_escape($row['owner'] ?? '') . '</td>';
			print '<td><span style="color:' . $color . ';">' . html_escape(ucfirst($row['state'])) . '</span></td>';
			$subnet_label = ($row['subnet'] && $row['mask']) ? $row['subnet'] . '/' . $row['mask'] : '';
			print '<td><a href="cereus_ipam_addresses.php?subnet_id=' . $row['subnet_id'] . '">' . html_escape($subnet_label) . '</a></td>';
			form_end_row();
		}

		if ($count >= 50) {
			print '<tr class="even"><td colspan="6" style="text-align:center;color:#999;">' . __('Results limited to 50. Refine your search for more specific results.', 'cereus_ipam') . '</td></tr>';
		}
	} else {
		print '<tr class="even"><td>' . __('No matching addresses found.', 'cereus_ipam') . '</td></tr>';
	}

	html_end_box();
}

/* ==================== Search: Subnets ==================== */

function cereus_ipam_search_subnets($query, $is_regex) {
	if ($is_regex) {
		$sql = "SELECT s.id, s.subnet, s.mask, s.description, s.gateway, sec.name AS section_name
				FROM plugin_cereus_ipam_subnets s
				LEFT JOIN plugin_cereus_ipam_sections sec ON sec.id = s.section_id
				WHERE (s.subnet REGEXP ? OR s.description REGEXP ? OR s.gateway REGEXP ?
					OR CONCAT(s.subnet, '/', s.mask) REGEXP ?)
				ORDER BY s.subnet LIMIT 50";
		$params = array($query, $query, $query, $query);
	} else {
		$safe = '%' . str_replace(array('%', '_'), array('\\%', '\\_'), $query) . '%';
		$sql = "SELECT s.id, s.subnet, s.mask, s.description, s.gateway, sec.name AS section_name
				FROM plugin_cereus_ipam_subnets s
				LEFT JOIN plugin_cereus_ipam_sections sec ON sec.id = s.section_id
				WHERE (s.subnet LIKE ? OR s.description LIKE ? OR s.gateway LIKE ?
					OR CONCAT(s.subnet, '/', s.mask) LIKE ?)
				ORDER BY s.subnet LIMIT 50";
		$params = array($safe, $safe, $safe, $safe);
	}

	$results = db_fetch_assoc_prepared($sql, $params);
	$count = cacti_sizeof($results);

	html_start_box(__('Subnets', 'cereus_ipam') . ' (' . $count . ')', '100%', '', '3', 'center', '');

	if ($count > 0) {
		$display_text = array(
			array('display' => __('Subnet', 'cereus_ipam'),      'align' => 'left'),
			array('display' => __('Description', 'cereus_ipam'), 'align' => 'left'),
			array('display' => __('Section', 'cereus_ipam'),     'align' => 'left'),
			array('display' => __('Gateway', 'cereus_ipam'),     'align' => 'left'),
			array('display' => __('Utilization', 'cereus_ipam'), 'align' => 'left'),
		);
		html_header($display_text);

		foreach ($results as $row) {
			$util = cereus_ipam_subnet_utilization($row['id']);
			form_alternate_row('sub_' . $row['id']);
			print '<td><a class="linkEditMain" href="cereus_ipam.php?action=edit&id=' . $row['id'] . '">' . html_escape($row['subnet'] . '/' . $row['mask']) . '</a>';
			print ' <a href="cereus_ipam_addresses.php?subnet_id=' . $row['id'] . '" title="' . __esc('View Addresses', 'cereus_ipam') . '"><i class="fa fa-list" style="font-size:11px;color:#999;"></i></a>';
			print ' <a href="cereus_ipam_addresses.php?action=visual&subnet_id=' . $row['id'] . '" title="' . __esc('Visual Map', 'cereus_ipam') . '"><i class="fa fa-th" style="font-size:11px;color:#999;"></i></a></td>';
			print '<td>' . html_escape($row['description'] ?? '') . '</td>';
			print '<td>' . html_escape($row['section_name'] ?? '') . '</td>';
			print '<td>' . html_escape($row['gateway'] ?? '') . '</td>';
			print '<td>' . cereus_ipam_utilization_bar($util['pct']) . '</td>';
			form_end_row();
		}
	} else {
		print '<tr class="even"><td>' . __('No matching subnets found.', 'cereus_ipam') . '</td></tr>';
	}

	html_end_box();
}

/* ==================== Search: VLANs ==================== */

function cereus_ipam_search_vlans($query, $is_regex) {
	if ($is_regex) {
		$sql = "SELECT id, vlan_number, name, description
				FROM plugin_cereus_ipam_vlans
				WHERE (CAST(vlan_number AS CHAR) REGEXP ? OR name REGEXP ? OR description REGEXP ?)
				ORDER BY vlan_number LIMIT 50";
		$params = array($query, $query, $query);
	} else {
		$safe = '%' . str_replace(array('%', '_'), array('\\%', '\\_'), $query) . '%';
		$sql = "SELECT id, vlan_number, name, description
				FROM plugin_cereus_ipam_vlans
				WHERE (CAST(vlan_number AS CHAR) LIKE ? OR name LIKE ? OR description LIKE ?)
				ORDER BY vlan_number LIMIT 50";
		$params = array($safe, $safe, $safe);
	}

	$results = db_fetch_assoc_prepared($sql, $params);
	$count = cacti_sizeof($results);

	html_start_box(__('VLANs', 'cereus_ipam') . ' (' . $count . ')', '100%', '', '3', 'center', '');

	if ($count > 0) {
		$display_text = array(
			array('display' => __('VLAN Number', 'cereus_ipam'), 'align' => 'left'),
			array('display' => __('Name', 'cereus_ipam'),        'align' => 'left'),
			array('display' => __('Description', 'cereus_ipam'), 'align' => 'left'),
			array('display' => __('Subnets', 'cereus_ipam'),     'align' => 'center'),
		);
		html_header($display_text);

		foreach ($results as $row) {
			$subnet_count = (int) db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_subnets WHERE vlan_id = ?", array($row['id']));
			form_alternate_row('vlan_' . $row['id']);
			print '<td><a class="linkEditMain" href="cereus_ipam_vlans.php?action=edit&id=' . $row['id'] . '">' . html_escape($row['vlan_number']) . '</a></td>';
			print '<td>' . html_escape($row['name']) . '</td>';
			print '<td>' . html_escape($row['description'] ?? '') . '</td>';
			print '<td class="center">';
			if ($subnet_count > 0) {
				print '<a href="cereus_ipam.php?vlan_id=' . $row['id'] . '">' . $subnet_count . '</a>';
			} else {
				print '0';
			}
			print '</td>';
			form_end_row();
		}
	} else {
		print '<tr class="even"><td>' . __('No matching VLANs found.', 'cereus_ipam') . '</td></tr>';
	}

	html_end_box();
}

/* ==================== Search: VRFs ==================== */

function cereus_ipam_search_vrfs($query, $is_regex) {
	if ($is_regex) {
		$sql = "SELECT id, name, rd, description
				FROM plugin_cereus_ipam_vrfs
				WHERE (name REGEXP ? OR rd REGEXP ? OR description REGEXP ?)
				ORDER BY name LIMIT 50";
		$params = array($query, $query, $query);
	} else {
		$safe = '%' . str_replace(array('%', '_'), array('\\%', '\\_'), $query) . '%';
		$sql = "SELECT id, name, rd, description
				FROM plugin_cereus_ipam_vrfs
				WHERE (name LIKE ? OR rd LIKE ? OR description LIKE ?)
				ORDER BY name LIMIT 50";
		$params = array($safe, $safe, $safe);
	}

	$results = db_fetch_assoc_prepared($sql, $params);
	$count = cacti_sizeof($results);

	html_start_box(__('VRFs', 'cereus_ipam') . ' (' . $count . ')', '100%', '', '3', 'center', '');

	if ($count > 0) {
		$display_text = array(
			array('display' => __('Name', 'cereus_ipam'),              'align' => 'left'),
			array('display' => __('Route Distinguisher', 'cereus_ipam'), 'align' => 'left'),
			array('display' => __('Description', 'cereus_ipam'),       'align' => 'left'),
			array('display' => __('Subnets', 'cereus_ipam'),           'align' => 'center'),
		);
		html_header($display_text);

		foreach ($results as $row) {
			$subnet_count = (int) db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_subnets WHERE vrf_id = ?", array($row['id']));
			form_alternate_row('vrf_' . $row['id']);
			print '<td><a class="linkEditMain" href="cereus_ipam_vrfs.php?action=edit&id=' . $row['id'] . '">' . html_escape($row['name']) . '</a></td>';
			print '<td>' . html_escape($row['rd'] ?? '') . '</td>';
			print '<td>' . html_escape($row['description'] ?? '') . '</td>';
			print '<td class="center">';
			if ($subnet_count > 0) {
				print '<a href="cereus_ipam.php?vrf_id=' . $row['id'] . '">' . $subnet_count . '</a>';
			} else {
				print '0';
			}
			print '</td>';
			form_end_row();
		}
	} else {
		print '<tr class="even"><td>' . __('No matching VRFs found.', 'cereus_ipam') . '</td></tr>';
	}

	html_end_box();
}

/* ==================== Search: Sections ==================== */

function cereus_ipam_search_sections($query, $is_regex) {
	if ($is_regex) {
		$sql = "SELECT id, name, description
				FROM plugin_cereus_ipam_sections
				WHERE (name REGEXP ? OR description REGEXP ?)
				ORDER BY name LIMIT 50";
		$params = array($query, $query);
	} else {
		$safe = '%' . str_replace(array('%', '_'), array('\\%', '\\_'), $query) . '%';
		$sql = "SELECT id, name, description
				FROM plugin_cereus_ipam_sections
				WHERE (name LIKE ? OR description LIKE ?)
				ORDER BY name LIMIT 50";
		$params = array($safe, $safe);
	}

	$results = db_fetch_assoc_prepared($sql, $params);
	$count = cacti_sizeof($results);

	html_start_box(__('Sections', 'cereus_ipam') . ' (' . $count . ')', '100%', '', '3', 'center', '');

	if ($count > 0) {
		$display_text = array(
			array('display' => __('Name', 'cereus_ipam'),        'align' => 'left'),
			array('display' => __('Description', 'cereus_ipam'), 'align' => 'left'),
			array('display' => __('Subnets', 'cereus_ipam'),     'align' => 'center'),
		);
		html_header($display_text);

		foreach ($results as $row) {
			$subnet_count = (int) db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_subnets WHERE section_id = ?", array($row['id']));
			form_alternate_row('sec_' . $row['id']);
			print '<td><a class="linkEditMain" href="cereus_ipam.php?action=section_edit&id=' . $row['id'] . '">' . html_escape($row['name']) . '</a></td>';
			print '<td>' . html_escape($row['description'] ?? '') . '</td>';
			print '<td class="center">';
			if ($subnet_count > 0) {
				print '<a href="cereus_ipam.php?section_id=' . $row['id'] . '">' . $subnet_count . '</a>';
			} else {
				print '0';
			}
			print '</td>';
			form_end_row();
		}
	} else {
		print '<tr class="even"><td>' . __('No matching sections found.', 'cereus_ipam') . '</td></tr>';
	}

	html_end_box();
}
