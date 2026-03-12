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
 | Cereus IPAM - Network Scan UI (Professional+)                           |
 +-------------------------------------------------------------------------+
*/

chdir('../../');
include('./include/auth.php');
include_once('./plugins/cereus_ipam/includes/constants.php');
include_once('./plugins/cereus_ipam/lib/license_check.php');
include_once('./plugins/cereus_ipam/lib/validation.php');
include_once('./plugins/cereus_ipam/lib/ip_utils.php');
include_once('./plugins/cereus_ipam/lib/functions.php');
include_once('./plugins/cereus_ipam/lib/changelog.php');
include_once('./plugins/cereus_ipam/lib/scanner.php');

$action = get_nfilter_request_var('action', '');

switch ($action) {
	case 'run_scan':
		cereus_ipam_run_scan_action();
		break;
	case 'run_arp_scan':
		cereus_ipam_run_arp_scan_action();
		break;
	case 'scan_progress':
		cereus_ipam_scan_progress();
		break;
	case 'apply_results':
		cereus_ipam_apply_scan_results();
		break;
	default:
		top_header();
		cereus_ipam_scan_page();
		bottom_footer();
		break;
}

/* ==================== Run Scan (AJAX) ==================== */

function cereus_ipam_run_scan_action() {
	if (!cereus_ipam_license_has_scanning()) {
		header('Content-Type: application/json');
		print json_encode(array('success' => false, 'error' => __('Scanning requires a Professional license.', 'cereus_ipam')));
		exit;
	}

	$subnet_id = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);

	if (!$subnet_id) {
		header('Content-Type: application/json');
		print json_encode(array('success' => false, 'error' => __('Invalid subnet.', 'cereus_ipam')));
		exit;
	}

	/* Mark scan as in-progress */
	set_config_option('cereus_ipam_scan_active_' . $subnet_id, time());

	/* Remove PHP execution time limit for large subnet scans (e.g. /16) */
	set_time_limit(0);

	/* Clear old scan results for this subnet */
	db_execute_prepared("DELETE FROM plugin_cereus_ipam_scan_results WHERE subnet_id = ?", array($subnet_id));

	/* Release session lock so progress polling AJAX can proceed concurrently */
	session_write_close();

	$result = cereus_ipam_scan_ping($subnet_id);

	/* Clear in-progress flag */
	set_config_option('cereus_ipam_scan_active_' . $subnet_id, '');

	cereus_ipam_changelog_record('scan', 'subnet', $subnet_id, null, array('alive' => $result['alive_count'] ?? 0));

	header('Content-Type: application/json');
	print json_encode($result, JSON_HEX_TAG | JSON_HEX_AMP);
	exit;
}

/* ==================== Run ARP Scan (AJAX) ==================== */

function cereus_ipam_run_arp_scan_action() {
	if (!cereus_ipam_license_has_scanning()) {
		header('Content-Type: application/json');
		print json_encode(array('success' => false, 'error' => __('Scanning requires a Professional license.', 'cereus_ipam')));
		exit;
	}

	$subnet_id = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);

	if (!$subnet_id) {
		header('Content-Type: application/json');
		print json_encode(array('success' => false, 'error' => __('Invalid subnet.', 'cereus_ipam')));
		exit;
	}

	/* Release session lock */
	session_write_close();

	$result = cereus_ipam_scan_arp($subnet_id);

	cereus_ipam_changelog_record('scan', 'subnet', $subnet_id, null, array('type' => 'arp', 'discovered' => $result['discovered'] ?? 0));

	header('Content-Type: application/json');
	print json_encode($result, JSON_HEX_TAG | JSON_HEX_AMP);
	exit;
}

/* ==================== Scan Progress (AJAX polling) ==================== */

function cereus_ipam_scan_progress() {
	$subnet_id = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);

	if (!$subnet_id) {
		header('Content-Type: application/json');
		print json_encode(array('error' => 'Invalid subnet'));
		exit;
	}

	$subnet = db_fetch_row_prepared("SELECT subnet, mask FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
	$version = cereus_ipam_ip_version($subnet['subnet']);
	$total = (int) cereus_ipam_subnet_size((int) $subnet['mask'], $version);

	$scanned = (int) db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_scan_results WHERE subnet_id = ?", array($subnet_id));
	$alive   = (int) db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_scan_results WHERE subnet_id = ? AND is_alive = 1", array($subnet_id));

	$active = read_config_option('cereus_ipam_scan_active_' . $subnet_id);
	$is_running = (!empty($active) && (time() - (int) $active) < 1800);

	$pct = ($total > 0) ? min(100, round(($scanned / $total) * 100)) : 0;

	header('Content-Type: application/json');
	print json_encode(array(
		'scanned'    => $scanned,
		'alive'      => $alive,
		'total'      => $total,
		'pct'        => $pct,
		'is_running' => $is_running,
	), JSON_HEX_TAG | JSON_HEX_AMP);
	exit;
}

/* ==================== Apply Scan Results ==================== */

function cereus_ipam_apply_scan_results() {
	if (!cereus_ipam_license_has_scanning()) {
		raise_message('cereus_ipam_lic', __('Scanning requires a Professional license.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_scan.php');
		exit;
	}

	$subnet_id = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);
	if (!$subnet_id) {
		header('Location: cereus_ipam_scan.php');
		exit;
	}

	/* Get scan results that are alive but not yet in IPAM */
	$results = db_fetch_assoc_prepared("SELECT sr.ip, sr.hostname, sr.mac_address
		FROM plugin_cereus_ipam_scan_results sr
		LEFT JOIN plugin_cereus_ipam_addresses a ON a.subnet_id = sr.subnet_id AND a.ip = sr.ip
		WHERE sr.subnet_id = ? AND sr.is_alive = 1 AND a.id IS NULL",
		array($subnet_id));

	$user_id = $_SESSION['sess_user_id'] ?? 0;
	$added = 0;

	foreach ($results as $r) {
		db_execute_prepared("INSERT IGNORE INTO plugin_cereus_ipam_addresses
			(subnet_id, ip, hostname, mac_address, state, last_seen, created_by)
			VALUES (?, ?, ?, ?, 'active', NOW(), ?)",
			array($subnet_id, $r['ip'], $r['hostname'], $r['mac_address'], $user_id));
		$added++;
	}

	raise_message('cereus_ipam_applied', __('Applied scan results: %d new addresses added.', $added, 'cereus_ipam'), MESSAGE_LEVEL_INFO);
	header('Location: cereus_ipam_scan.php?subnet_id=' . $subnet_id);
	exit;
}

/* ==================== Scan Page ==================== */

function cereus_ipam_scan_page() {
	if (!cereus_ipam_license_has_scanning()) {
		html_start_box(__('Network Scanning', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr class="even"><td style="padding:8px 15px;"><em>' . __('Network scanning requires a Professional license.', 'cereus_ipam') . '</em></td></tr>';
		html_end_box();
		return;
	}

	$subnet_id = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);

	/* Subnet selector */
	$subnets = db_fetch_assoc("SELECT s.id, CONCAT(s.subnet, '/', s.mask) AS cidr, s.description, sec.name AS section_name
		FROM plugin_cereus_ipam_subnets s
		LEFT JOIN plugin_cereus_ipam_sections sec ON sec.id = s.section_id
		ORDER BY s.subnet");

	html_start_box(__('Network Scan', 'cereus_ipam'), '100%', '', '3', 'center', '');
	?>
	<tr class='even'>
		<td>
			<form id='form_scan' action='cereus_ipam_scan.php'>
				<table class='filterTable'>
					<tr>
						<td><?php print __('Subnet', 'cereus_ipam'); ?></td>
						<td>
							<select id='subnet_id' name='subnet_id'>
								<option value=''><?php print __('Select a subnet...', 'cereus_ipam'); ?></option>
								<?php
								foreach ($subnets as $s) {
									$label = $s['cidr'] . ' - ' . $s['description'] . ' (' . $s['section_name'] . ')';
									print "<option value='" . $s['id'] . "'" . ($subnet_id == $s['id'] ? ' selected' : '') . ">" . html_escape($label) . "</option>\n";
								}
								?>
							</select>
						</td>
						<td>
							<input type='button' class='ui-button' id='btn_scan' value='<?php print __esc('Ping Scan', 'cereus_ipam'); ?>' <?php print ($subnet_id ? '' : 'disabled'); ?>>
							<input type='button' class='ui-button' id='btn_arp_scan' value='<?php print __esc('ARP Scan (SNMP)', 'cereus_ipam'); ?>' <?php print ($subnet_id ? '' : 'disabled'); ?>>
							<?php if ($subnet_id): ?>
							<input type='button' class='ui-button' id='btn_apply' value='<?php print __esc('Apply Results to IPAM', 'cereus_ipam'); ?>'>
							<?php endif; ?>
						</td>
						<td id='scan_status'></td>
					</tr>
				</table>
			</form>
			<script type='text/javascript'>
			$(function() {
				var progressTimer = null;

				function updateProgress(sid) {
					$.ajax({
						url: 'cereus_ipam_scan.php',
						type: 'GET',
						data: { action: 'scan_progress', subnet_id: sid },
						dataType: 'json',
						timeout: 5000,
						success: function(data) {
							var html = '<div style="display:inline-flex;align-items:center;gap:8px;">';
							html += '<div style="width:150px;height:16px;background:#e0e0e0;border-radius:3px;overflow:hidden;">';
							html += '<div style="width:' + data.pct + '%;height:100%;background:#1976D2;border-radius:3px;transition:width 0.3s;"></div></div>';
							html += '<span style="font-size:12px;white-space:nowrap;">' + data.scanned + '/' + data.total + ' <?php print __esc('IPs checked', 'cereus_ipam'); ?>, ';
							html += '<strong style="color:#4CAF50;">' + data.alive + '</strong> <?php print __esc('alive', 'cereus_ipam'); ?>';
							html += ' (' + data.pct + '%)</span></div>';
							$('#scan_status').html(html);
						}
					});
				}

				function startProgress(sid) {
					stopProgress();
					updateProgress(sid);
					progressTimer = setInterval(function() { updateProgress(sid); }, 2000);
				}

				function stopProgress() {
					if (progressTimer) {
						clearInterval(progressTimer);
						progressTimer = null;
					}
				}

				$('#subnet_id').change(function() {
					var sid = $(this).val();
					if (sid) {
						$('#btn_scan').prop('disabled', false);
						loadPageNoHeader('cereus_ipam_scan.php?header=false&subnet_id=' + sid);
					} else {
						$('#btn_scan').prop('disabled', true);
					}
				});

				$('#btn_scan').click(function() {
					var sid = $('#subnet_id').val();
					if (!sid) return;
					var btn = $(this);
					btn.prop('disabled', true).val('<?php print __esc('Scanning...', 'cereus_ipam'); ?>');
					$('#scan_status').html('<i><?php print __esc('Starting scan...', 'cereus_ipam'); ?></i>');

					startProgress(sid);

					$.ajax({
						url: 'cereus_ipam_scan.php',
						type: 'POST',
						data: { action: 'run_scan', subnet_id: sid, __csrf_magic: csrfMagicToken },
						dataType: 'json',
						timeout: 1800000,
						success: function(data) {
							stopProgress();
							if (data.success) {
								$('#scan_status').html('<span style="color:#4CAF50;font-weight:bold;"><?php print __esc('Scan complete:', 'cereus_ipam'); ?> ' + data.alive_count + ' <?php print __esc('hosts alive', 'cereus_ipam'); ?></span>');
								loadPageNoHeader('cereus_ipam_scan.php?header=false&subnet_id=' + sid);
							} else {
								$('#scan_status').html('<span style="color:#F44336;"><?php print __esc('Error:', 'cereus_ipam'); ?> ' + data.error + '</span>');
							}
						},
						error: function(xhr, status) {
							stopProgress();
							var msg = (status === 'timeout') ? '<?php print __esc('Scan timed out. Check results below.', 'cereus_ipam'); ?>' : '<?php print __esc('Scan request failed.', 'cereus_ipam'); ?>';
							$('#scan_status').html('<span style="color:#F44336;">' + msg + '</span>');
							loadPageNoHeader('cereus_ipam_scan.php?header=false&subnet_id=' + sid);
						},
						complete: function() {
							stopProgress();
							btn.prop('disabled', false).val('<?php print __esc('Scan Now', 'cereus_ipam'); ?>');
						}
					});
				});

				$('#btn_arp_scan').click(function() {
				var sid = $('#subnet_id').val();
				if (!sid) return;
				var btn = $(this);
				btn.prop('disabled', true).val('<?php print __esc('Scanning ARP...', 'cereus_ipam'); ?>');
				$('#scan_status').html('<i><?php print __esc('Running SNMP ARP scan...', 'cereus_ipam'); ?></i>');

				$.ajax({
					url: 'cereus_ipam_scan.php',
					type: 'POST',
					data: { action: 'run_arp_scan', subnet_id: sid, __csrf_magic: csrfMagicToken },
					dataType: 'json',
					timeout: 120000,
					success: function(data) {
						if (data.success) {
							$('#scan_status').html('<span style="color:#4CAF50;font-weight:bold;"><?php print __esc('ARP Scan complete:', 'cereus_ipam'); ?> ' + data.discovered + ' <?php print __esc('MAC+IP pairs discovered', 'cereus_ipam'); ?></span>');
							loadPageNoHeader('cereus_ipam_scan.php?header=false&subnet_id=' + sid);
						} else {
							$('#scan_status').html('<span style="color:#F44336;"><?php print __esc('Error:', 'cereus_ipam'); ?> ' + data.error + '</span>');
						}
					},
					error: function() {
						$('#scan_status').html('<span style="color:#F44336;"><?php print __esc('ARP scan request failed.', 'cereus_ipam'); ?></span>');
					},
					complete: function() {
						btn.prop('disabled', false).val('<?php print __esc('ARP Scan (SNMP)', 'cereus_ipam'); ?>');
					}
				});
			});

			$('#btn_apply').click(function() {
					document.location = 'cereus_ipam_scan.php?action=apply_results&subnet_id=' + $('#subnet_id').val();
				});
			});
			</script>
		</td>
	</tr>
	<?php
	html_end_box();

	/* Show scan results if a subnet is selected — only alive hosts */
	if ($subnet_id > 0) {
		$results = db_fetch_assoc_prepared("SELECT sr.*, a.id AS addr_id, a.state AS addr_state
			FROM plugin_cereus_ipam_scan_results sr
			LEFT JOIN plugin_cereus_ipam_addresses a ON a.subnet_id = sr.subnet_id AND a.ip = sr.ip
			WHERE sr.subnet_id = ? AND sr.is_alive = 1
			ORDER BY INET_ATON(sr.ip)",
			array($subnet_id));

		$subnet_info = db_fetch_row_prepared("SELECT subnet, mask, last_scanned FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));

		$title = __('Scan Results for %s/%s', html_escape($subnet_info['subnet']), $subnet_info['mask'], 'cereus_ipam');
		if (!empty($subnet_info['last_scanned'])) {
			$title .= ' - ' . __('Last scan: %s', $subnet_info['last_scanned'], 'cereus_ipam');
		}

		html_start_box($title, '100%', '', '3', 'center', '');

		$display_text = array(
			array('display' => __('IP Address', 'cereus_ipam'), 'align' => 'left'),
			array('display' => __('Alive', 'cereus_ipam'),      'align' => 'center'),
			array('display' => __('Hostname', 'cereus_ipam'),   'align' => 'left'),
			array('display' => __('MAC', 'cereus_ipam'),        'align' => 'left'),
			array('display' => __('In IPAM', 'cereus_ipam'),    'align' => 'center'),
			array('display' => __('Scanned', 'cereus_ipam'),    'align' => 'left'),
		);
		html_header($display_text);

		if (cacti_sizeof($results)) {
			foreach ($results as $r) {
				form_alternate_row('scan_' . $r['id']);

				form_selectable_cell(html_escape($r['ip']), $r['id']);

				$alive_text = $r['is_alive']
					? "<span class='deviceUp'>" . __('Yes', 'cereus_ipam') . "</span>"
					: "<span class='deviceDown'>" . __('No', 'cereus_ipam') . "</span>";
				form_selectable_cell($alive_text, $r['id'], '', 'center');

				form_selectable_cell(html_escape($r['hostname'] ?? ''), $r['id']);
				form_selectable_cell(html_escape($r['mac_address'] ?? ''), $r['id']);

				$in_ipam = $r['addr_id']
					? "<span class='deviceUp'>" . __('Yes', 'cereus_ipam') . " (" . html_escape(ucfirst($r['addr_state'])) . ")</span>"
					: "<span style='color:#9E9E9E;'>" . __('No', 'cereus_ipam') . "</span>";
				form_selectable_cell($in_ipam, $r['id'], '', 'center');

				form_selectable_cell($r['scanned_at'], $r['id']);

				form_end_row();
			}
		} else {
			print '<tr><td colspan="6"><em>' . __('No scan results. Click "Scan Now" to start.', 'cereus_ipam') . '</em></td></tr>';
		}

		html_end_box();
	}
}
