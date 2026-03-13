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

	/* Clear any previous stop flag */
	set_config_option('cereus_ipam_scan_stop_' . $subnet_id, '');

	/* Mark scan as in-progress */
	set_config_option('cereus_ipam_scan_active_' . $subnet_id, time());

	/* Remove PHP execution time limit for large subnet scans (e.g. /16) */
	set_time_limit(0);

	/* Keep running even if the HTTP connection is dropped (Apache Timeout,
	 * browser close, proxy timeout). Scan results are written to the DB
	 * progressively, so the progress poller can still track completion. */
	ignore_user_abort(true);

	/* Clear old scan results for this subnet */
	db_execute_prepared("DELETE FROM plugin_cereus_ipam_scan_results WHERE subnet_id = ?", array($subnet_id));

	/* Release session lock so progress polling AJAX can proceed concurrently */
	session_write_close();

	$result = cereus_ipam_scan_ping($subnet_id);

	/* Clear in-progress and stop flags */
	set_config_option('cereus_ipam_scan_active_' . $subnet_id, '');
	set_config_option('cereus_ipam_scan_stop_' . $subnet_id, '');

	cereus_ipam_changelog_record('scan', 'subnet', $subnet_id, null, array(
		'alive'   => $result['alive_count'] ?? 0,
		'stopped' => $result['stopped'] ?? false,
	));

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

	/* Fetch recent results since last_id for live feed */
	$last_id = get_filter_request_var('last_id', FILTER_VALIDATE_INT);
	if (empty($last_id)) {
		$last_id = 0;
	}

	$recent = db_fetch_assoc_prepared("SELECT id, ip, is_alive, hostname
		FROM plugin_cereus_ipam_scan_results
		WHERE subnet_id = ? AND id > ?
		ORDER BY id ASC
		LIMIT 200",
		array($subnet_id, $last_id));

	$results = array();
	$max_id = $last_id;

	if (cacti_sizeof($recent)) {
		foreach ($recent as $r) {
			$results[] = array(
				'ip'       => $r['ip'],
				'alive'    => (int) $r['is_alive'],
				'hostname' => $r['hostname'] ?? '',
			);

			if ((int) $r['id'] > $max_id) {
				$max_id = (int) $r['id'];
			}
		}
	}

	header('Content-Type: application/json');
	print json_encode(array(
		'scanned'    => $scanned,
		'alive'      => $alive,
		'total'      => $total,
		'pct'        => $pct,
		'is_running' => $is_running,
		'results'    => $results,
		'last_id'    => $max_id,
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
							<input type='button' class='ui-button ui-state-error' id='btn_stop' value='<?php print __esc('Stop Scan', 'cereus_ipam'); ?>' style='display:none;'>
							<?php if ($subnet_id): ?>
							<input type='button' class='ui-button' id='btn_apply' value='<?php print __esc('Apply Results to IPAM', 'cereus_ipam'); ?>'>
							<?php endif; ?>
						</td>
						<td id='scan_status'></td>
					</tr>
				</table>
			</form>
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
	<?php

	/* JavaScript for scan controls and live feed */
	?>
	<script type='text/javascript'>
	$(function() {
		var progressTimer = null;
		var lastId = 0;
		var scanRunning = false;
		var checkDoneTimer = null;
		var autoScroll = true;

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

				if (r.alive) {
					html += '<div style="padding:1px 0;"><span style="color:#666;">[' + ts + ']</span> ';
					html += '<span style="color:#4CAF50; font-weight:bold;">&#9679;</span> ';
					html += '<span style="color:#4CAF50;">' + escapeHtml(r.ip) + '</span>';
					if (r.hostname) {
						html += ' <span style="color:#81C784;">(' + escapeHtml(r.hostname) + ')</span>';
					}
					html += ' <span style="color:#4CAF50;">- <?php print __esc('alive', 'cereus_ipam'); ?></span>';
					html += '</div>';
				} else {
					html += '<div style="padding:1px 0;"><span style="color:#666;">[' + ts + ']</span> ';
					html += '<span style="color:#555;">&#9679;</span> ';
					html += '<span style="color:#777;">' + escapeHtml(r.ip) + '</span>';
					html += ' <span style="color:#555;">- <?php print __esc('no response', 'cereus_ipam'); ?></span>';
					html += '</div>';
				}
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

					/* Check if scan finished (for background-mode detection) */
					if (!data.is_running && scanRunning) {
						scanFinished(sid, data);
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
			lastId = 0;
			$feed.empty();
			$('#scan_live_container').show();
			$('#btn_stop').show();
			$('#btn_scan').prop('disabled', true).val('<?php print __esc('Scanning...', 'cereus_ipam'); ?>');
			$('#btn_arp_scan').prop('disabled', true);
		}

		function scanFinished(sid, data) {
			scanRunning = false;
			stopProgress();
			if (checkDoneTimer) {
				clearInterval(checkDoneTimer);
				checkDoneTimer = null;
			}

			$('#btn_stop').hide();
			$('#btn_scan').prop('disabled', false).val('<?php print __esc('Ping Scan', 'cereus_ipam'); ?>');
			$('#btn_arp_scan').prop('disabled', false);

			var aliveCount = data ? (data.alive || data.alive_count || 0) : '?';
			var stopped = data && data.stopped;
			var msg = stopped
				? '<?php print __esc('Scan stopped', 'cereus_ipam'); ?>'
				: '<?php print __esc('Scan complete', 'cereus_ipam'); ?>';

			$('#scan_status').html('<span style="color:' + (stopped ? '#FF9800' : '#4CAF50') + ';font-weight:bold;">' + msg + ': ' + aliveCount + ' <?php print __esc('hosts alive', 'cereus_ipam'); ?></span>');

			/* Append completion line to feed */
			var ts = new Date().toLocaleTimeString();
			$feed.append('<div style="padding:3px 0; border-top:1px solid #444; margin-top:4px; color:' + (stopped ? '#FF9800' : '#4CAF50') + '; font-weight:bold;">[' + ts + '] ' + msg + '</div>');
			if (autoScroll) {
				$feed.scrollTop($feed[0].scrollHeight);
			}

			/* Reload the results table below */
			loadPageNoHeader('cereus_ipam_scan.php?header=false&subnet_id=' + sid);
		}

		$('#subnet_id').change(function() {
			var sid = $(this).val();
			if (sid) {
				$('#btn_scan').prop('disabled', false);
				$('#btn_arp_scan').prop('disabled', false);
				loadPageNoHeader('cereus_ipam_scan.php?header=false&subnet_id=' + sid);
			} else {
				$('#btn_scan').prop('disabled', true);
				$('#btn_arp_scan').prop('disabled', true);
			}
		});

		$('#btn_scan').click(function() {
			var sid = $('#subnet_id').val();
			if (!sid) return;

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
					if (data.success) {
						scanFinished(sid, data);
					} else {
						scanRunning = false;
						stopProgress();
						$('#btn_stop').hide();
						$('#btn_scan').prop('disabled', false).val('<?php print __esc('Ping Scan', 'cereus_ipam'); ?>');
						$('#btn_arp_scan').prop('disabled', false);
						$('#scan_status').html('<span style="color:#F44336;"><?php print __esc('Error:', 'cereus_ipam'); ?> ' + data.error + '</span>');
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
	});
	</script>
	<?php

	/* Show scan results if a subnet is selected */
	if ($subnet_id > 0) {
		cereus_ipam_scan_results_table($subnet_id);
	}
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

	/* Title */
	$title = __('Scan Results for %s/%s', html_escape($subnet_info['subnet']), $subnet_info['mask'], 'cereus_ipam');
	if (!empty($subnet_info['last_scanned'])) {
		$title .= ' - ' . __('Last scan: %s', $subnet_info['last_scanned'], 'cereus_ipam');
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
