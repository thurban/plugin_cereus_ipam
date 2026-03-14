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
	case 'stop_scan':
		cereus_ipam_stop_scan_action();
		break;
	case 'scan_progress':
		cereus_ipam_scan_progress();
		break;
	case 'apply_results':
		cereus_ipam_apply_scan_results();
		break;
	case 'force_clear':
		cereus_ipam_force_clear_scan();
		break;
	case 'run_conflict_check':
		cereus_ipam_run_conflict_check_action();
		break;
	case 'results_table':
		cereus_ipam_results_table_ajax();
		break;
	default:
		top_header();
		cereus_ipam_scan_page();
		bottom_footer();
		break;
}

/* ==================== Scan State Helpers ==================== */

/**
 * Check if a scan is actively running for a given subnet.
 * Uses active flag + heartbeat to detect truly running vs crashed scans.
 * Stale scans (heartbeat > 5 min old) are automatically cleared.
 *
 * @return array  ['running' => bool, 'stale' => bool, 'age' => int seconds]
 */
function cereus_ipam_check_scan_state($subnet_id) {
	$active = read_config_option('cereus_ipam_scan_active_' . $subnet_id);

	if (empty($active)) {
		return array('running' => false, 'stale' => false, 'age' => 0);
	}

	$start_age = time() - (int) $active;

	/* Check heartbeat — scanner updates this every chunk */
	$heartbeat = read_config_option('cereus_ipam_scan_heartbeat_' . $subnet_id);
	$hb_age = !empty($heartbeat) ? (time() - (int) $heartbeat) : $start_age;

	/* Consider stale if heartbeat is older than 2 minutes, or start is older than 30 minutes */
	if ($hb_age > 120 || $start_age > 1800) {
		/* Auto-clear crashed scan */
		set_config_option('cereus_ipam_scan_active_' . $subnet_id, '');
		set_config_option('cereus_ipam_scan_stop_' . $subnet_id, '');
		set_config_option('cereus_ipam_scan_heartbeat_' . $subnet_id, '');

		return array('running' => false, 'stale' => true, 'age' => $start_age);
	}

	return array('running' => true, 'stale' => false, 'age' => $start_age);
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

	/* Check if a scan is already running for this subnet */
	$state = cereus_ipam_check_scan_state($subnet_id);
	if ($state['running']) {
		header('Content-Type: application/json');
		print json_encode(array('success' => false, 'error' => __('A scan is already running for this subnet.', 'cereus_ipam'), 'already_running' => true));
		exit;
	}

	/* ---- Clean state: clear ALL previous scan artifacts ---- */
	set_config_option('cereus_ipam_scan_stop_' . $subnet_id, '');
	set_config_option('cereus_ipam_scan_result_' . $subnet_id, '');
	set_config_option('cereus_ipam_scan_heartbeat_' . $subnet_id, time());
	set_config_option('cereus_ipam_scan_active_' . $subnet_id, time());

	/* Remove PHP execution time limit for large subnet scans (e.g. /16) */
	set_time_limit(0);

	/* Keep running even if the HTTP connection is dropped (Apache Timeout,
	 * browser close, proxy timeout). Scan results are written to the DB
	 * progressively, so the progress poller can still track completion. */
	ignore_user_abort(true);

	/* Clear old scan results for this subnet */
	db_execute_prepared("DELETE FROM plugin_cereus_ipam_scan_results WHERE subnet_id = ?", array($subnet_id));

	/* Register shutdown handler to clear flags even if the scan crashes.
	   This prevents a crashed scan from blocking future scans. */
	register_shutdown_function(function () use ($subnet_id) {
		$active = db_fetch_cell_prepared("SELECT value FROM settings WHERE name = ?",
			array('cereus_ipam_scan_active_' . $subnet_id));
		if (!empty($active)) {
			set_config_option('cereus_ipam_scan_active_' . $subnet_id, '');
			set_config_option('cereus_ipam_scan_stop_' . $subnet_id, '');
			set_config_option('cereus_ipam_scan_heartbeat_' . $subnet_id, '');
		}
	});

	/* Release session lock so progress polling AJAX can proceed concurrently */
	session_write_close();

	$result = cereus_ipam_scan_ping($subnet_id);

	cereus_ipam_changelog_record('scan', 'subnet', $subnet_id, null, array(
		'alive'   => $result['alive_count'] ?? 0,
		'stopped' => $result['stopped'] ?? false,
		'method'  => $result['method'] ?? '',
	));

	/* Include method label for display */
	$method_labels = array(
		'fping'        => 'fping (ICMP)',
		'nmap'         => 'Nmap (-sn ping scan)',
		'ping'         => __('Native Ping (ICMP)', 'cereus_ipam'),
		'tcp-parallel' => __('TCP Connect', 'cereus_ipam'),
	);
	$result['method_label'] = $method_labels[$result['method']] ?? $result['method'];

	/* Persist scan summary BEFORE clearing active flag — avoids a race
	   where the progress poller sees is_running=false but has no result. */
	set_config_option('cereus_ipam_scan_result_' . $subnet_id, json_encode(array(
		'alive_count'   => $result['alive_count'] ?? 0,
		'dead_count'    => $result['dead_count'] ?? 0,
		'total_scanned' => $result['total_scanned'] ?? 0,
		'method'        => $result['method'] ?? '',
		'method_label'  => $result['method_label'] ?? '',
		'command'       => $result['command'] ?? '',
		'elapsed'       => $result['elapsed'] ?? 0,
		'exit_code'     => $result['exit_code'] ?? 0,
		'stderr'        => $result['stderr'] ?? '',
		'stopped'       => $result['stopped'] ?? false,
		'success'       => $result['success'] ?? true,
	)));

	/* NOW clear in-progress flags (after result is persisted) */
	set_config_option('cereus_ipam_scan_active_' . $subnet_id, '');
	set_config_option('cereus_ipam_scan_stop_' . $subnet_id, '');
	set_config_option('cereus_ipam_scan_heartbeat_' . $subnet_id, '');

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

	/* Keep running even if the HTTP connection is dropped */
	set_time_limit(0);
	ignore_user_abort(true);

	/* Release session lock */
	session_write_close();

	$result = cereus_ipam_scan_arp($subnet_id);

	cereus_ipam_changelog_record('scan', 'subnet', $subnet_id, null, array('type' => 'arp', 'discovered' => $result['discovered'] ?? 0));

	header('Content-Type: application/json');
	print json_encode($result, JSON_HEX_TAG | JSON_HEX_AMP);
	exit;
}

/* ==================== Stop Scan (AJAX) ==================== */

function cereus_ipam_stop_scan_action() {
	$subnet_id = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);

	if (!$subnet_id) {
		header('Content-Type: application/json');
		print json_encode(array('success' => false, 'error' => 'Invalid subnet'));
		exit;
	}

	/* Set the stop flag — the scanner checks this between chunks */
	set_config_option('cereus_ipam_scan_stop_' . $subnet_id, time());

	header('Content-Type: application/json');
	print json_encode(array('success' => true));
	exit;
}

/* ==================== Force Clear Stale Scan (AJAX) ==================== */

function cereus_ipam_force_clear_scan() {
	$subnet_id = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);

	if (!$subnet_id) {
		header('Content-Type: application/json');
		print json_encode(array('success' => false, 'error' => 'Invalid subnet'));
		exit;
	}

	set_config_option('cereus_ipam_scan_active_' . $subnet_id, '');
	set_config_option('cereus_ipam_scan_stop_' . $subnet_id, '');
	set_config_option('cereus_ipam_scan_heartbeat_' . $subnet_id, '');

	header('Content-Type: application/json');
	print json_encode(array('success' => true));
	exit;
}

/* ==================== Run Conflict Check (AJAX, deferred) ==================== */

function cereus_ipam_run_conflict_check_action() {
	$subnet_id = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);

	if (!$subnet_id) {
		header('Content-Type: application/json');
		print json_encode(array('success' => false, 'error' => 'Invalid subnet'));
		exit;
	}

	/* Send response immediately, run detection in background */
	header('Content-Type: application/json');
	print json_encode(array('success' => true));

	if (function_exists('fastcgi_finish_request')) {
		fastcgi_finish_request();
	} else {
		if (ob_get_level()) {
			ob_end_flush();
		}
		flush();
	}

	set_time_limit(0);
	ignore_user_abort(true);

	cereus_ipam_post_scan_conflict_check($subnet_id);
	exit;
}

/* ==================== Results Table (AJAX partial) ==================== */

function cereus_ipam_results_table_ajax() {
	$subnet_id = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);

	if (!$subnet_id) {
		print '';
		exit;
	}

	cereus_ipam_scan_results_table($subnet_id);
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

	$scan_state = cereus_ipam_check_scan_state($subnet_id);
	$is_running = $scan_state['running'];

	$pct = ($total > 0) ? min(100, round(($scanned / $total) * 100)) : 0;

	/* Fetch recent ALIVE results since last_id for live feed.
	 * Only alive hosts are shown in the feed — down hosts would flood
	 * the display (especially with nmap which batch-inserts them).
	 * We track max_id across ALL rows (not just alive) to avoid
	 * re-fetching the same down-host rows on the next poll. */
	$last_id = get_filter_request_var('last_id', FILTER_VALIDATE_INT);
	if (empty($last_id)) {
		$last_id = 0;
	}

	/* Advance last_id past all rows (alive + down) so we don't re-scan them */
	$new_max_id = (int) db_fetch_cell_prepared("SELECT COALESCE(MAX(id), 0)
		FROM plugin_cereus_ipam_scan_results
		WHERE subnet_id = ? AND id > ?",
		array($subnet_id, $last_id));

	$max_id = ($new_max_id > $last_id) ? $new_max_id : $last_id;

	/* Only fetch alive hosts for the live feed display */
	$recent = db_fetch_assoc_prepared("SELECT id, ip, is_alive, hostname
		FROM plugin_cereus_ipam_scan_results
		WHERE subnet_id = ? AND id > ? AND is_alive = 1
		ORDER BY id ASC
		LIMIT 200",
		array($subnet_id, $last_id));

	$results = array();

	if (cacti_sizeof($recent)) {
		foreach ($recent as $r) {
			$results[] = array(
				'ip'       => $r['ip'],
				'alive'    => (int) $r['is_alive'],
				'hostname' => $r['hostname'] ?? '',
			);
		}
	}

	/* If scan has finished, include the persisted result summary so the
	   UI can show statistics even when the main AJAX response was lost */
	$scan_result = null;
	if (!$is_running) {
		$saved = read_config_option('cereus_ipam_scan_result_' . $subnet_id);
		if (!empty($saved)) {
			$scan_result = json_decode($saved, true);
		}
	}

	header('Content-Type: application/json');
	print json_encode(array(
		'scanned'      => $scanned,
		'alive'        => $alive,
		'total'        => $total,
		'pct'          => $pct,
		'is_running'   => $is_running,
		'results'      => $results,
		'last_id'      => $max_id,
		'scan_result'  => $scan_result,
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
	$subnets = db_fetch_assoc("SELECT s.id, CONCAT(s.subnet, '/', s.mask) AS cidr, s.description, s.scan_enabled, sec.name AS section_name
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
							<input type='button' class='ui-button ui-state-error' id='btn_stop' value='<?php print __esc('Stop Scan', 'cereus_ipam'); ?>' style='display:none;'>
							<input type='button' class='ui-button' id='btn_force_clear' value='<?php print __esc('Clear Stale Scan', 'cereus_ipam'); ?>' style='display:none;'>
							<?php if ($subnet_id): ?>
							<input type='button' class='ui-button' id='btn_apply' value='<?php print __esc('Apply Results to IPAM', 'cereus_ipam'); ?>'>
							<?php endif; ?>
						</td>
						<td id='scan_status'></td>
					</tr>
				</table>
			</form>
			<div id='scan_method_info' style='margin-top:4px; padding:2px 0; font-size:12px; color:#888;'>
				<?php
				$method = cereus_ipam_scan_get_method();
				$method_labels = array(
					'fping'        => 'fping (ICMP)',
					'nmap'         => 'Nmap (-sn ping scan)',
					'ping'         => __('Native Ping (ICMP)', 'cereus_ipam'),
					'tcp-parallel' => __('TCP Connect', 'cereus_ipam'),
					'tcp'          => __('TCP Connect', 'cereus_ipam'),
					'auto'         => __('Auto', 'cereus_ipam'),
				);
				$method_label = $method_labels[$method] ?? $method;

				/* Build full command preview for nmap/fping */
				$cmd_preview = '';
				$preview_cidr = '{subnet}';
				$binary_path = '';
				$timeout_val = cereus_ipam_scan_get_timeout();

				if ($method === 'nmap') {
					$binary_path = cereus_ipam_scan_find_nmap();
				} elseif ($method === 'fping') {
					$binary_path = cereus_ipam_scan_find_fping();
				}

				if (($method === 'nmap' || $method === 'fping') && !empty($binary_path)) {
					/* Get CIDR of selected subnet for command preview */
					$preview_cidr = '{subnet}';
					if ($subnet_id > 0) {
						$preview_subnet = db_fetch_row_prepared("SELECT subnet, mask FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
						if (cacti_sizeof($preview_subnet)) {
							$preview_cidr = $preview_subnet['subnet'] . '/' . $preview_subnet['mask'];
						}
					}

					if ($method === 'nmap') {
						$ts = max(1, (int) ceil($timeout_val / 1000));
						$cmd_preview = $binary_path
							. ' -sn -oX - --no-stylesheet --host-timeout ' . $ts . 's -T4 '
							. $preview_cidr;
					} else {
						$cmd_preview = $binary_path
							. ' -g -r 1 -t ' . (int) $timeout_val . ' '
							. $preview_cidr;
					}
				}

				print '<i class="fa fa-cog"></i> ' . __('Scan Method:', 'cereus_ipam') . ' <strong>' . html_escape($method_label) . '</strong>';

				if (!empty($binary_path)) {
					print ' &mdash; ' . html_escape($binary_path);
				} elseif ($method === 'nmap' || $method === 'fping') {
					print ' &mdash; <span style="color:#F44336;">' . __('not found', 'cereus_ipam') . '</span>';
				}

				if (!empty($cmd_preview)) {
					print '<br><i class="fa fa-terminal" style="margin-right:4px;"></i>';
					print '<code id="scan_cmd_preview" style="font-size:12px; background:#1a1a2e; color:#0f0; padding:2px 8px; border-radius:3px; user-select:all;">'
						. html_escape($cmd_preview) . '</code>';
				}
				?>
			</div>
		</td>
	</tr>
	<?php
	html_end_box();

	/* Live scan output area — hidden until a scan starts */
	?>
	<div id='scan_live_container' style='display:none; margin-top:2px;'>
		<table class='cactiTable' style='width:100%;'>
			<tbody>
				<tr class='tableHeader'>
					<th class='tableSubHeaderColumn' style='text-align:left;'><?php print __('Live Scan Results', 'cereus_ipam'); ?></th>
				</tr>
				<tr>
					<td style='padding:0;'>
						<div id='scan_live_feed' style='height:300px; overflow-y:auto; background:#1a1a2e; color:#e0e0e0; font-family:monospace; font-size:12px; padding:8px; border:1px solid #444;'>
						</div>
					</td>
				</tr>
				<tr>
					<td style='padding:4px 8px; font-size:11px; color:#888;'>
						<span id='scan_live_summary'></span>
					</td>
				</tr>
			</tbody>
		</table>
	</div>
	<div id='scan_summary_container' style='display:none; margin-top:2px;'></div>
	<?php

	/* Detect if a scan is currently running for the selected subnet */
	$scan_running_on_load = false;
	if ($subnet_id > 0) {
		$load_state = cereus_ipam_check_scan_state($subnet_id);
		$scan_running_on_load = $load_state['running'];
	}

	/* JavaScript for scan controls and live feed */
	?>
	<script type='text/javascript'>
	$(function() {
		var progressTimer = null;
		var lastId = 0;
		var scanRunning = false;
		var scanStartTime = 0;
		var checkDoneTimer = null;
		var autoScroll = true;
		var lastProgressScanned = -1;
		var staleProgressCount = 0;

		/* Subnet CIDR map and command template for live preview updates */
		var subnetCidrs = {
			<?php
			foreach ($subnets as $s) {
				print "'" . (int) $s['id'] . "': " . json_encode($s['cidr']) . ",\n\t\t\t";
			}
			?>
		};
		var subnetScheduled = {
			<?php
			foreach ($subnets as $s) {
				print "'" . (int) $s['id'] . "': " . ((int) $s['scan_enabled'] ? 'true' : 'false') . ",\n\t\t\t";
			}
			?>
		};
		var conflictAlertsEnabled = <?php print (read_config_option('cereus_ipam_conflict_alerts_enabled') == 'on') ? 'true' : 'false'; ?>;
		var cmdTemplate = <?php print json_encode($cmd_preview); ?>;

		var currentPreviewCidr = <?php print json_encode($preview_cidr); ?>;

		function updateCmdPreview() {
			var $el = $('#scan_cmd_preview');
			if (!$el.length || !cmdTemplate) return;
			var sid = $('#subnet_id').val();
			var cidr = (sid && subnetCidrs[sid]) ? subnetCidrs[sid] : '{subnet}';
			var updated = cmdTemplate.replace(currentPreviewCidr, cidr);
			currentPreviewCidr = cidr;
			$el.text(updated);
		}

		var $feed = $('#scan_live_feed');

		/* Track if user has scrolled up manually */
		$feed.on('scroll', function() {
			var el = this;
			autoScroll = (el.scrollTop + el.clientHeight >= el.scrollHeight - 20);
		});

		function appendResults(results) {
			if (!results || !results.length) return;

			var html = '';
			for (var i = 0; i < results.length; i++) {
				var r = results[i];
				var ts = new Date().toLocaleTimeString();

				/* Live feed only shows alive hosts (down hosts are filtered
				 * server-side to avoid flooding the display) */
				html += '<div style="padding:1px 0;"><span style="color:#666;">[' + ts + ']</span> ';
				html += '<span style="color:#4CAF50; font-weight:bold;">&#9679;</span> ';
				html += '<span style="color:#4CAF50;">' + escapeHtml(r.ip) + '</span>';
				if (r.hostname) {
					html += ' <span style="color:#81C784;">(' + escapeHtml(r.hostname) + ')</span>';
				}
				html += ' <span style="color:#4CAF50;">- <?php print __esc('alive', 'cereus_ipam'); ?></span>';
				html += '</div>';
			}

			$feed.append(html);

			if (autoScroll) {
				$feed.scrollTop($feed[0].scrollHeight);
			}
		}

		function escapeHtml(text) {
			var d = document.createElement('div');
			d.appendChild(document.createTextNode(text));
			return d.innerHTML;
		}

		function statCard(value, label, color, icon) {
			return '<div style="flex:1; text-align:center; padding:18px 10px; border-right:1px solid #ddd; min-width:120px;">'
				+ '<div style="font-size:28px; font-weight:bold; color:' + color + ';">' + value + '</div>'
				+ '<div style="font-size:11px; color:#888; margin-top:5px;"><i class="fa ' + icon + '"></i> ' + label + '</div>'
				+ '</div>';
		}

		function showScanDashboard(data) {
			if (!data) return;

			var aliveCount = parseInt(data.alive_count || data.alive || 0);
			var deadCount = parseInt(data.dead_count || (data.scanned ? data.scanned - aliveCount : 0) || 0);
			var totalScanned = parseInt(data.total_scanned || data.scanned || 0);
			if (totalScanned === 0) totalScanned = aliveCount + deadCount;
			var elapsed = parseFloat(data.elapsed || 0);
			var methodLabel = data.method_label || data.method || '';
			var subnet = data.subnet || '';
			var command = data.command || '';
			var exitCode = data.exit_code ? parseInt(data.exit_code) : 0;
			var hasError = exitCode > 0 || (data.stderr && data.stderr.length > 0);
			var stopped = data.stopped || false;
			var isSuccess = data.success !== false && !hasError;
			var alivePct = totalScanned > 0 ? ((aliveCount / totalScanned) * 100).toFixed(1) : 0;

			/* Format duration */
			var durationText;
			if (elapsed >= 3600) {
				var hrs = Math.floor(elapsed / 3600);
				var mins = Math.floor((elapsed % 3600) / 60);
				durationText = hrs + 'h ' + mins + 'm';
			} else if (elapsed >= 60) {
				var mins = Math.floor(elapsed / 60);
				var secs = Math.round(elapsed % 60);
				durationText = mins + 'm ' + secs + 's';
			} else if (elapsed > 0) {
				durationText = elapsed.toFixed(1) + 's';
			} else {
				durationText = '-';
			}

			/* Status determination */
			var statusIcon, statusText, statusColor, headerBg;
			if (stopped) {
				statusIcon = 'fa-stop-circle';
				statusText = '<?php print __esc('Scan Stopped', 'cereus_ipam'); ?>';
				statusColor = '#FF9800';
				headerBg = 'linear-gradient(135deg, #3e2e1a 0%, #4a3520 100%)';
			} else if (!isSuccess) {
				statusIcon = 'fa-exclamation-triangle';
				statusText = '<?php print __esc('Scan Failed', 'cereus_ipam'); ?>';
				statusColor = '#F44336';
				headerBg = 'linear-gradient(135deg, #3e1a1a 0%, #4a2020 100%)';
			} else {
				statusIcon = 'fa-check-circle';
				statusText = '<?php print __esc('Scan Complete', 'cereus_ipam'); ?>';
				statusColor = '#4CAF50';
				headerBg = 'linear-gradient(135deg, #1a3e1a 0%, #204a20 100%)';
			}

			var html = '<div style="border:1px solid #555; border-radius:5px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,0.15);">';

			/* Header bar */
			html += '<div style="padding:10px 15px; background:' + headerBg + ';">';
			html += '<span style="color:' + statusColor + '; font-size:15px; font-weight:bold;">';
			html += '<i class="fa ' + statusIcon + '"></i> ' + statusText + '</span>';
			if (subnet) {
				html += '<span style="color:#bbb; margin-left:15px; font-size:13px;">' + escapeHtml(subnet) + '</span>';
			}
			html += '</div>';

			/* Stat cards row */
			html += '<div style="display:flex; flex-wrap:wrap; border-bottom:1px solid #ddd;">';
			html += statCard(totalScanned, '<?php print __esc('Hosts Scanned', 'cereus_ipam'); ?>', '#2c3e50', 'fa-server');
			html += statCard(aliveCount, '<?php print __esc('Alive', 'cereus_ipam'); ?>', '#4CAF50', 'fa-check-circle');
			html += statCard(deadCount, '<?php print __esc('No Response', 'cereus_ipam'); ?>', '#9E9E9E', 'fa-times-circle');
			html += statCard(durationText, '<?php print __esc('Duration', 'cereus_ipam'); ?>', '#2196F3', 'fa-clock-o');
			html += '</div>';

			/* Alive/Dead ratio bar */
			if (totalScanned > 0) {
				var barColor = parseFloat(alivePct) > 50 ? '#4CAF50' : (parseFloat(alivePct) > 20 ? '#FF9800' : '#2196F3');
				html += '<div style="padding:10px 15px; border-bottom:1px solid #ddd;">';
				html += '<div style="display:flex; align-items:center; gap:12px;">';
				html += '<span style="font-size:12px; color:#888; white-space:nowrap;"><?php print __esc('Alive Ratio', 'cereus_ipam'); ?></span>';
				html += '<div style="flex:1; height:22px; background:#e0e0e0; border-radius:11px; overflow:hidden; position:relative;">';
				html += '<div style="width:' + alivePct + '%; height:100%; background:' + barColor + '; border-radius:11px; transition:width 0.6s ease;"></div>';
				html += '<span style="position:absolute; top:50%; left:50%; transform:translate(-50%,-50%); font-size:11px; font-weight:bold; color:#333; text-shadow:0 0 3px rgba(255,255,255,0.8);">';
				html += alivePct + '% (' + aliveCount + ' / ' + totalScanned + ')</span>';
				html += '</div>';
				html += '</div>';
				html += '</div>';
			}

			/* Details section */
			html += '<div style="padding:10px 15px;">';

			/* Error section */
			if (hasError) {
				html += '<div style="margin-top:8px; padding:10px 12px; background:#fff5f5; border:1px solid #ffcdd2; border-radius:4px;">';
				html += '<div style="color:#F44336; font-weight:bold; margin-bottom:4px;"><i class="fa fa-exclamation-triangle"></i> <?php print __esc('Error', 'cereus_ipam'); ?></div>';
				if (exitCode > 0) {
					html += '<div style="font-size:12px; color:#c62828;"><?php print __esc('Exit code:', 'cereus_ipam'); ?> ' + exitCode + '</div>';
				}
				if (data.stderr) {
					html += '<pre style="margin:4px 0 0; padding:6px 10px; background:#2d1a1a; color:#ef9a9a; border-radius:3px; font-size:12px; white-space:pre-wrap; word-break:break-all;">' + escapeHtml(data.stderr) + '</pre>';
				}
				html += '</div>';
			}

			html += '</div>'; /* close details */
			html += '</div>'; /* close outer container */

			$('#scan_summary_container').html(html).show();
		}

		function updateProgress(sid) {
			$.ajax({
				url: 'cereus_ipam_scan.php',
				type: 'GET',
				data: { action: 'scan_progress', subnet_id: sid, last_id: lastId },
				dataType: 'json',
				timeout: 5000,
				success: function(data) {
					/* Progress bar */
					var html = '<div style="display:inline-flex;align-items:center;gap:8px;">';
					html += '<div style="width:200px;height:16px;background:#e0e0e0;border-radius:3px;overflow:hidden;">';
					html += '<div style="width:' + data.pct + '%;height:100%;background:#1976D2;border-radius:3px;transition:width 0.3s;"></div></div>';
					html += '<span style="font-size:12px;white-space:nowrap;">' + data.scanned + '/' + data.total + ' <?php print __esc('IPs checked', 'cereus_ipam'); ?>, ';
					html += '<strong style="color:#4CAF50;">' + data.alive + '</strong> <?php print __esc('alive', 'cereus_ipam'); ?>';
					html += ' (' + data.pct + '%)</span></div>';
					$('#scan_status').html(html);

					/* Live summary under feed */
					$('#scan_live_summary').html(
						'<?php print __esc('Scanned:', 'cereus_ipam'); ?> ' + data.scanned + '/' + data.total +
						' &mdash; <?php print __esc('Alive:', 'cereus_ipam'); ?> <strong style="color:#4CAF50;">' + data.alive + '</strong>' +
						' &mdash; <?php print __esc('No response:', 'cereus_ipam'); ?> ' + (data.scanned - data.alive)
					);

					/* Append new results */
					if (data.results && data.results.length > 0) {
						appendResults(data.results);
					}

					lastId = data.last_id;

					/* Stale progress detection: if scanned count hasn't changed
					   for multiple polls, the scan process likely crashed. */
					if (scanRunning) {
						if (data.scanned === lastProgressScanned) {
							staleProgressCount++;
							if (staleProgressCount >= 20) {
								/* ~30 seconds with no progress — auto-complete as failed */
								scanFinished(sid, {
									success: false,
									alive_count: data.alive,
									dead_count: data.scanned - data.alive,
									total_scanned: data.scanned,
									error: '<?php print __esc('Scan process stopped responding.', 'cereus_ipam'); ?>'
								});
								return;
							}
							if (staleProgressCount >= 10) {
								/* ~15 seconds — show force clear option */
								$('#btn_force_clear').show();
							}
						} else {
							staleProgressCount = 0;
							lastProgressScanned = data.scanned;
						}
					}

					/* Check if scan finished (detected by server-side state) */
					if (!data.is_running && scanRunning) {
						if (data.scan_result) {
							/* Definitive: persisted result exists, scan truly completed
							   (result is written BEFORE active flag is cleared) */
							scanFinished(sid, data.scan_result);
						} else {
							/* No persisted result — could be a race (poller fired before
							   scan POST was processed) or a crash. Use time guard. */
							var elapsed = Date.now() - scanStartTime;
							if (elapsed >= 3000) {
								scanFinished(sid, data);
							}
						}
					}
				}
			});
		}

		function startProgress(sid) {
			stopProgress();
			updateProgress(sid);
			progressTimer = setInterval(function() { updateProgress(sid); }, 1500);
		}

		function stopProgress() {
			if (progressTimer) {
				clearInterval(progressTimer);
				progressTimer = null;
			}
		}

		function scanStarted() {
			scanRunning = true;
			scanFinishedCalled = false;
			scanStartTime = Date.now();
			lastId = 0;
			lastProgressScanned = -1;
			staleProgressCount = 0;
			$feed.empty();
			$('#scan_summary_container').hide().empty();

			/* Show method info in the live feed header */
			var methodInfo = $('#scan_method_info').find('strong').text() || '';
			if (methodInfo) {
				$feed.append('<div style="padding:2px 0; color:#1976D2; font-weight:bold;"><i class="fa fa-cog"></i> <?php print __esc('Scan method:', 'cereus_ipam'); ?> ' + escapeHtml(methodInfo) + '</div><div style="border-bottom:1px solid #333; margin-bottom:4px;"></div>');
			}

			$('#scan_live_container').show();
			$('#btn_stop').show();
			$('#btn_scan').prop('disabled', true).val('<?php print __esc('Scanning...', 'cereus_ipam'); ?>');
			$('#btn_arp_scan').prop('disabled', true);
		}

		var scanFinishedCalled = false;
		function scanFinished(sid, data) {
			if (scanFinishedCalled) return; /* Idempotent: safe to call multiple times */
			scanFinishedCalled = true;
			scanRunning = false;
			stopProgress();
			if (checkDoneTimer) {
				clearInterval(checkDoneTimer);
				checkDoneTimer = null;
			}

			$('#btn_stop').hide();
			$('#btn_force_clear').hide();
			$('#btn_scan').prop('disabled', false).val('<?php print __esc('Ping Scan', 'cereus_ipam'); ?>');
			$('#btn_arp_scan').prop('disabled', false);

			/* Update the top command preview with the actual executed command */
			if (data && data.command) {
				var $el = $('#scan_cmd_preview');
				if ($el.length) {
					$el.text(data.command);
				}
				cmdTemplate = data.command;
			}

			/* Hide live feed, show dashboard */
			$('#scan_live_container').hide();
			$('#scan_status').html('');

			showScanDashboard(data);

			/* Run conflict detection if:
			   - Conflict alerts are enabled globally
			   - Subnet does NOT have scheduled scans (those run detection in the poller)
			   - Scan was successful and not stopped */
			if (conflictAlertsEnabled && !subnetScheduled[sid] && data && data.success !== false && !data.stopped) {
				$.ajax({
					url: 'cereus_ipam_scan.php',
					type: 'POST',
					data: { action: 'run_conflict_check', subnet_id: sid, __csrf_magic: csrfMagicToken },
					dataType: 'json',
					timeout: 60000
				});
			}

			/* Reload only the results table */
			$.get('cereus_ipam_scan.php', { action: 'results_table', subnet_id: sid }, function(html) {
				$('#scan_results_wrapper').html(html);
			});
		}

		$('#subnet_id').change(function() {
			var sid = $(this).val();
			$('#scan_summary_container').hide().empty();
			if (sid) {
				$('#btn_scan').prop('disabled', false);
				$('#btn_arp_scan').prop('disabled', false);
				updateCmdPreview();
				loadPageNoHeader('cereus_ipam_scan.php?header=false&subnet_id=' + sid);
			} else {
				$('#btn_scan').prop('disabled', true);
				$('#btn_arp_scan').prop('disabled', true);
				updateCmdPreview();
			}
		});

		$('#btn_scan').click(function() {
			var sid = $('#subnet_id').val();
			if (!sid || scanRunning) return;

			scanStarted();
			$('#scan_status').html('<i><?php print __esc('Starting scan...', 'cereus_ipam'); ?></i>');

			startProgress(sid);

			$.ajax({
				url: 'cereus_ipam_scan.php',
				type: 'POST',
				data: { action: 'run_scan', subnet_id: sid, __csrf_magic: csrfMagicToken },
				dataType: 'json',
				timeout: 1800000,
				success: function(data) {
					if (data.already_running) {
						/* Another scan is running — show as running state */
						$('#scan_status').html('<span style="color:#FF9800;font-weight:bold;"><i class="fa fa-spinner fa-spin"></i> <?php print __esc('A scan is already running for this subnet.', 'cereus_ipam'); ?></span>');
						return;
					}
					if (data.success || data.alive_count !== undefined) {
						/* Scan completed (possibly with errors) — show summary */
						scanFinished(sid, data);
					} else {
						/* Pre-scan failure (license, invalid subnet) */
						scanRunning = false;
						stopProgress();
						$('#scan_live_container').hide();
						$('#btn_stop').hide();
						$('#btn_scan').prop('disabled', false).val('<?php print __esc('Ping Scan', 'cereus_ipam'); ?>');
						$('#btn_arp_scan').prop('disabled', false);
						var errMsg = data.error || data.stderr || '<?php print __esc('Unknown error', 'cereus_ipam'); ?>';
						$('#scan_status').html('<span style="color:#F44336;"><?php print __esc('Error:', 'cereus_ipam'); ?> ' + escapeHtml(errMsg) + '</span>');
					}
				},
				error: function(xhr, status) {
					/* The HTTP connection may drop (Apache Timeout) but the
					   scan continues server-side (ignore_user_abort). Keep
					   polling for progress until the scan finishes. */
					$('#scan_status').html('<i><?php print __esc('Scan running in background...', 'cereus_ipam'); ?></i>');
					if (!progressTimer) {
						startProgress(sid);
					}
				}
			});
		});

		$('#btn_stop').click(function() {
			var sid = $('#subnet_id').val();
			if (!sid) return;

			$(this).prop('disabled', true).val('<?php print __esc('Stopping...', 'cereus_ipam'); ?>');

			$.ajax({
				url: 'cereus_ipam_scan.php',
				type: 'POST',
				data: { action: 'stop_scan', subnet_id: sid, __csrf_magic: csrfMagicToken },
				dataType: 'json',
				timeout: 10000
			});

			/* The scanner will stop within a few seconds at the next chunk boundary.
			   The progress poller will detect is_running=false and call scanFinished. */
		});

		$('#btn_force_clear').click(function() {
			var sid = $('#subnet_id').val();
			if (!sid) return;

			$.ajax({
				url: 'cereus_ipam_scan.php',
				type: 'POST',
				data: { action: 'force_clear', subnet_id: sid, __csrf_magic: csrfMagicToken },
				dataType: 'json',
				timeout: 10000,
				success: function(data) {
					scanRunning = false;
					stopProgress();
					$('#scan_live_container').hide();
					$('#btn_stop').hide();
					$('#btn_force_clear').hide();
					$('#btn_scan').prop('disabled', false).val('<?php print __esc('Ping Scan', 'cereus_ipam'); ?>');
					$('#btn_arp_scan').prop('disabled', false);
					$('#scan_status').html('<span style="color:#4CAF50;"><?php print __esc('Stale scan cleared. You can start a new scan.', 'cereus_ipam'); ?></span>');
				}
			});
		});

		$('#btn_arp_scan').click(function() {
			var sid = $('#subnet_id').val();
			if (!sid) return;
			var btn = $(this);
			btn.prop('disabled', true).val('<?php print __esc('Scanning ARP...', 'cereus_ipam'); ?>');
			$('#btn_scan').prop('disabled', true);
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
					$('#btn_scan').prop('disabled', false);
				}
			});
		});

		$('#btn_apply').click(function() {
			document.location = 'cereus_ipam_scan.php?action=apply_results&subnet_id=' + $('#subnet_id').val();
		});

		/* On page load: resume running scan UI or show persisted dashboard */
		var initialScanRunning = <?php print ($scan_running_on_load ? 'true' : 'false'); ?>;
		var initialSubnetId = <?php print ($subnet_id ? (int) $subnet_id : '0'); ?>;

		if (initialScanRunning && initialSubnetId) {
			/* A scan is in progress — enter scanning state */
			scanRunning = true;
			scanStartTime = Date.now() - 10000; /* pretend started 10s ago to skip race guard */
			$('#scan_summary_container').hide().empty();
			$('#scan_live_container').show();
			$('#btn_stop').show();
			$('#btn_force_clear').show(); /* Always show force-clear when resuming a running scan */
			$('#btn_scan').prop('disabled', true).val('<?php print __esc('Scanning...', 'cereus_ipam'); ?>');
			$('#btn_arp_scan').prop('disabled', true);
			$('#scan_status').html('<i><i class="fa fa-spinner fa-spin"></i> <?php print __esc('Scan in progress...', 'cereus_ipam'); ?></i>');
			startProgress(initialSubnetId);
		} else if (typeof window._initialScanData !== 'undefined' && window._initialScanData) {
			/* Show persisted scan results dashboard */
			showScanDashboard(window._initialScanData);
		}
	});
	</script>
	<?php

	/* Inject persisted scan result for dashboard display on page load */
	if ($subnet_id > 0 && !$scan_running_on_load) {
		$saved_json = read_config_option('cereus_ipam_scan_result_' . $subnet_id);
		if (!empty($saved_json)) {
			$saved_data = json_decode($saved_json, true);
			if (is_array($saved_data) && (($saved_data['total_scanned'] ?? 0) > 0 || ($saved_data['alive_count'] ?? 0) > 0)) {
				$sub_info = db_fetch_row_prepared("SELECT subnet, mask FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
				if (cacti_sizeof($sub_info)) {
					$saved_data['subnet'] = $sub_info['subnet'] . '/' . $sub_info['mask'];
				}
				print '<script type="text/javascript">window._initialScanData = '
					. json_encode($saved_data, JSON_HEX_TAG | JSON_HEX_AMP) . ";</script>\n";
			}
		}
	}

	/* Show scan results if a subnet is selected */
	print '<div id="scan_results_wrapper">';
	if ($subnet_id > 0) {
		cereus_ipam_scan_results_table($subnet_id);
	}
	print '</div>';
}

/* ==================== Scan Results Table (paginated) ==================== */

function cereus_ipam_scan_results_table($subnet_id) {
	$subnet_info = db_fetch_row_prepared("SELECT subnet, mask, last_scanned FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));

	if (!cacti_sizeof($subnet_info)) {
		return;
	}

	/* Filter state — persist in session */
	if (isset_request_var('clear')) {
		unset_request_var('show_dead');
		unset_request_var('page');
	}

	load_current_session_value('show_dead', 'sess_cipam_scan_show_dead_' . $subnet_id, '');
	load_current_session_value('page',      'sess_cipam_scan_page_' . $subnet_id,      '1');

	$show_dead = get_request_var('show_dead');
	$show_dead = ($show_dead === 'true' || $show_dead === '1');

	$page = max(1, (int) get_request_var('page'));

	$rows = read_config_option('num_rows_table');
	if (empty($rows) || $rows < 1) {
		$rows = 30;
	}

	/* Counts for summary (always unfiltered) */
	$alive_count = (int) db_fetch_cell_prepared(
		"SELECT COUNT(*) FROM plugin_cereus_ipam_scan_results WHERE subnet_id = ? AND is_alive = 1",
		array($subnet_id));
	$dead_count = (int) db_fetch_cell_prepared(
		"SELECT COUNT(*) FROM plugin_cereus_ipam_scan_results WHERE subnet_id = ? AND is_alive = 0",
		array($subnet_id));

	/* Filtered query */
	$sql_where = "WHERE sr.subnet_id = ?";
	$sql_params = array($subnet_id);

	if (!$show_dead) {
		$sql_where .= " AND sr.is_alive = 1";
	}

	$total_rows = (int) db_fetch_cell_prepared(
		"SELECT COUNT(*) FROM plugin_cereus_ipam_scan_results sr $sql_where",
		$sql_params);

	/* Clamp page to valid range */
	$total_pages = max(1, ceil($total_rows / $rows));
	if ($page > $total_pages) {
		$page = 1;
	}

	$offset = ($page - 1) * $rows;

	$results = db_fetch_assoc_prepared(
		"SELECT sr.*, a.id AS addr_id, a.state AS addr_state
		FROM plugin_cereus_ipam_scan_results sr
		LEFT JOIN plugin_cereus_ipam_addresses a ON a.subnet_id = sr.subnet_id AND a.ip = sr.ip
		$sql_where
		ORDER BY INET_ATON(sr.ip)
		LIMIT $offset, $rows",
		$sql_params);

	/* Determine which scan method produced these results */
	$last_scan_type = db_fetch_cell_prepared(
		"SELECT scan_type FROM plugin_cereus_ipam_scan_results WHERE subnet_id = ? ORDER BY id DESC LIMIT 1",
		array($subnet_id));

	$scan_type_labels = array(
		'ping' => __('Ping', 'cereus_ipam'),
		'nmap' => 'Nmap',
		'arp'  => __('ARP', 'cereus_ipam'),
		'snmp' => 'SNMP',
		'dns'  => 'DNS',
	);
	$scan_type_label = isset($scan_type_labels[$last_scan_type]) ? $scan_type_labels[$last_scan_type] : '';

	/* Title */
	$title = __('Scan Results for %s/%s', html_escape($subnet_info['subnet']), $subnet_info['mask'], 'cereus_ipam');
	if (!empty($subnet_info['last_scanned'])) {
		$title .= ' - ' . __('Last scan: %s', $subnet_info['last_scanned'], 'cereus_ipam');
	}
	if (!empty($scan_type_label)) {
		$title .= ' [' . $scan_type_label . ']';
	}
	$title .= ' (' . __('%d alive, %d no response', $alive_count, $dead_count, 'cereus_ipam') . ')';

	/* Navigation bar — uses document.location for page changes */
	$nav_url = 'cereus_ipam_scan.php?subnet_id=' . $subnet_id . '&show_dead=' . ($show_dead ? 'true' : '');
	$nav = html_nav_bar($nav_url, MAX_DISPLAY_PAGES, $page, $rows, $total_rows, 7, __('Results', 'cereus_ipam'));

	html_start_box($title, '100%', '', '3', 'center', '');

	/* Filter row */
	?>
	<tr class='even'>
		<td>
			<table class='filterTable'>
				<tr>
					<td>
						<label style='cursor:pointer;'>
							<input type='checkbox' id='chk_show_dead' <?php print ($show_dead ? 'checked' : ''); ?>
								onchange="document.location='cereus_ipam_scan.php?subnet_id=<?php print (int) $subnet_id; ?>&show_dead=' + (this.checked ? 'true' : '') + '&page=1';">
							<?php print __('Show %d hosts with no response', $dead_count, 'cereus_ipam'); ?>
						</label>
					</td>
				</tr>
			</table>
		</td>
	</tr>
	<?php

	html_end_box();

	print $nav;

	html_start_box('', '100%', '', '3', 'center', '');

	$display_text = array(
		array('display' => __('IP Address', 'cereus_ipam'), 'align' => 'left'),
		array('display' => __('Status', 'cereus_ipam'),     'align' => 'center'),
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
				? "<span class='deviceUp'>" . __('Alive', 'cereus_ipam') . "</span>"
				: "<span class='deviceDown'>" . __('No Response', 'cereus_ipam') . "</span>";
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
		print '<tr><td colspan="6"><em>' . __('No scan results. Click "Ping Scan" to start.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box(false);

	if (cacti_sizeof($results)) {
		print $nav;
	}
}
