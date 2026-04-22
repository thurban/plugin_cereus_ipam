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
 | Cereus IPAM - Reports (Professional+)                                   |
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
include_once('./plugins/cereus_ipam/lib/report_scheduler.php');

$action = get_nfilter_request_var('action', '');

switch ($action) {
	case 'export_csv':
		cereus_ipam_report_export_csv();
		break;
	case 'export_pdf':
		cereus_ipam_report_export_pdf();
		break;
	case 'send_now':
		cereus_ipam_report_send_now();
		break;
	default:
		top_header();
		cereus_ipam_reports_page();
		bottom_footer();
		break;
}

/* ==================== Main Reports Page ==================== */

function cereus_ipam_reports_page() {
	/* License gate */
	if (!cereus_ipam_license_at_least('professional')) {
		html_start_box(__('IPAM Reports', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr class="even"><td style="padding:8px 15px;">';
		print '<em>' . __('IPAM Reports require a Professional or Enterprise license. Please upgrade to access subnet utilization, address state summaries, stale address detection, and reconciliation reports.', 'cereus_ipam') . '</em>';
		print '</td></tr>';
		html_end_box();
		return;
	}

	/* Filter handling */
	if (isset_request_var('clear')) {
		kill_session_var('sess_cipam_rpt_type');
		kill_session_var('sess_cipam_rpt_section');
		kill_session_var('sess_cipam_rpt_status');
		kill_session_var('sess_cipam_rpt_days');
		kill_session_var('sess_cipam_rpt_subnet');
		unset_request_var('report_type');
		unset_request_var('section_id');
		unset_request_var('status_filter');
		unset_request_var('stale_days');
		unset_request_var('subnet_id');
	}

	load_current_session_value('report_type',    'sess_cipam_rpt_type',    'utilization');
	load_current_session_value('section_id',     'sess_cipam_rpt_section', '-1');
	load_current_session_value('status_filter',  'sess_cipam_rpt_status',  'all');
	load_current_session_value('stale_days',     'sess_cipam_rpt_days',    '90');
	load_current_session_value('subnet_id',      'sess_cipam_rpt_subnet',  '');

	$report_type   = get_request_var('report_type');
	$section_id    = get_request_var('section_id');
	$status_filter = get_request_var('status_filter');
	$stale_days    = get_request_var('stale_days');
	$subnet_id     = get_request_var('subnet_id');

	/* Build dropdowns */
	$sections = cereus_ipam_get_sections_tree();
	$section_dropdown = array('-1' => __('All Sections', 'cereus_ipam'));
	foreach ($sections as $s) {
		$prefix = str_repeat('-- ', $s['depth']);
		$section_dropdown[$s['id']] = $prefix . $s['name'];
	}

	$subnets_list = db_fetch_assoc("SELECT s.id, CONCAT(s.subnet, '/', s.mask) AS cidr, s.description, sec.name AS section_name
		FROM plugin_cereus_ipam_subnets s
		LEFT JOIN plugin_cereus_ipam_sections sec ON sec.id = s.section_id
		ORDER BY s.subnet, s.mask");

	/* Filter bar */
	html_start_box(__('IPAM Reports', 'cereus_ipam'), '100%', '', '3', 'center', '');
	?>
	<tr class='even noprint'>
		<td>
			<form id='form_cipam_reports' action='cereus_ipam_reports.php'>
				<table class='filterTable'>
					<tr>
						<td><?php print __('Report', 'cereus_ipam'); ?></td>
						<td>
							<select id='report_type'>
								<option value='utilization' <?php print ($report_type == 'utilization' ? 'selected' : ''); ?>><?php print __('Subnet Utilization', 'cereus_ipam'); ?></option>
								<option value='states' <?php print ($report_type == 'states' ? 'selected' : ''); ?>><?php print __('Address State Summary', 'cereus_ipam'); ?></option>
								<option value='stale' <?php print ($report_type == 'stale' ? 'selected' : ''); ?>><?php print __('Stale Addresses', 'cereus_ipam'); ?></option>
								<option value='reconciliation' <?php print ($report_type == 'reconciliation' ? 'selected' : ''); ?>><?php print __('Reconciliation', 'cereus_ipam'); ?></option>
							</select>
						</td>
						<?php /* Utilization filters */ ?>
						<td class='filter_utilization filter_states' style='display:none;'><?php print __('Section', 'cereus_ipam'); ?></td>
						<td class='filter_utilization filter_states' style='display:none;'>
							<select id='section_id'>
								<?php
								foreach ($section_dropdown as $k => $v) {
									print "<option value='" . $k . "'" . ($section_id == $k ? ' selected' : '') . ">" . html_escape($v) . "</option>\n";
								}
								?>
							</select>
						</td>
						<td class='filter_utilization' style='display:none;'><?php print __('Status', 'cereus_ipam'); ?></td>
						<td class='filter_utilization' style='display:none;'>
							<select id='status_filter'>
								<option value='all' <?php print ($status_filter == 'all' ? 'selected' : ''); ?>><?php print __('All', 'cereus_ipam'); ?></option>
								<option value='ok' <?php print ($status_filter == 'ok' ? 'selected' : ''); ?>><?php print __('OK', 'cereus_ipam'); ?></option>
								<option value='warning' <?php print ($status_filter == 'warning' ? 'selected' : ''); ?>><?php print __('Warning (75-90%%)', 'cereus_ipam'); ?></option>
								<option value='critical' <?php print ($status_filter == 'critical' ? 'selected' : ''); ?>><?php print __('Critical (>=90%%)', 'cereus_ipam'); ?></option>
							</select>
						</td>
						<?php /* Stale filters */ ?>
						<td class='filter_stale' style='display:none;'><?php print __('Older Than', 'cereus_ipam'); ?></td>
						<td class='filter_stale' style='display:none;'>
							<select id='stale_days'>
								<option value='30' <?php print ($stale_days == '30' ? 'selected' : ''); ?>><?php print __('30 Days', 'cereus_ipam'); ?></option>
								<option value='60' <?php print ($stale_days == '60' ? 'selected' : ''); ?>><?php print __('60 Days', 'cereus_ipam'); ?></option>
								<option value='90' <?php print ($stale_days == '90' ? 'selected' : ''); ?>><?php print __('90 Days', 'cereus_ipam'); ?></option>
								<option value='180' <?php print ($stale_days == '180' ? 'selected' : ''); ?>><?php print __('180 Days', 'cereus_ipam'); ?></option>
							</select>
						</td>
						<?php /* Reconciliation filters */ ?>
						<td class='filter_reconciliation' style='display:none;'><?php print __('Subnet', 'cereus_ipam'); ?></td>
						<td class='filter_reconciliation' style='display:none;'>
							<select id='subnet_id'>
								<option value=''><?php print __('Select a subnet...', 'cereus_ipam'); ?></option>
								<?php
								foreach ($subnets_list as $sn) {
									$label = $sn['cidr'] . ' - ' . $sn['description'] . ' (' . $sn['section_name'] . ')';
									print "<option value='" . $sn['id'] . "'" . ($subnet_id == $sn['id'] ? ' selected' : '') . ">" . html_escape($label) . "</option>\n";
								}
								?>
							</select>
						</td>
						<td>
							<span>
								<input type='button' class='ui-button' id='go' value='<?php print __esc('Go', 'cereus_ipam'); ?>'>
								<input type='button' class='ui-button' id='clear' value='<?php print __esc('Clear', 'cereus_ipam'); ?>'>
								<input type='button' class='ui-button' id='export_csv' value='<?php print __esc('Export CSV', 'cereus_ipam'); ?>'>
								<input type='button' class='ui-button' id='export_pdf' value='<?php print __esc('Export PDF', 'cereus_ipam'); ?>'>
								<input type='button' class='ui-button' id='send_report_now' value='<?php print __esc('Send Email Now', 'cereus_ipam'); ?>' title='<?php print __esc('Send the scheduled email report immediately using the configured recipients and settings.', 'cereus_ipam'); ?>'>
								<span id='send_report_result' style='margin-left:8px;font-size:.9em;'></span>
							</span>
						</td>
					</tr>
				</table>
			</form>
			<script type='text/javascript'>
			function showReportFilters() {
				var rt = $('#report_type').val();
				$('.filter_utilization, .filter_states, .filter_stale, .filter_reconciliation').hide();
				if (rt == 'utilization') {
					$('.filter_utilization').show();
					$('.filter_states').show();
				} else if (rt == 'states') {
					$('.filter_states').show();
				} else if (rt == 'stale') {
					$('.filter_stale').show();
				} else if (rt == 'reconciliation') {
					$('.filter_reconciliation').show();
				}
			}
			function applyFilter() {
				var rt = $('#report_type').val();
				var url = 'cereus_ipam_reports.php?header=false&report_type=' + rt;
				if (rt == 'utilization' || rt == 'states') {
					url += '&section_id=' + $('#section_id').val();
				}
				if (rt == 'utilization') {
					url += '&status_filter=' + $('#status_filter').val();
				}
				if (rt == 'stale') {
					url += '&stale_days=' + $('#stale_days').val();
				}
				if (rt == 'reconciliation') {
					url += '&subnet_id=' + $('#subnet_id').val();
				}
				loadPageNoHeader(url);
			}
			function exportCSV() {
				var rt = $('#report_type').val();
				var url = 'cereus_ipam_reports.php?action=export_csv&report_type=' + rt;
				if (rt == 'utilization' || rt == 'states') {
					url += '&section_id=' + $('#section_id').val();
				}
				if (rt == 'utilization') {
					url += '&status_filter=' + $('#status_filter').val();
				}
				if (rt == 'stale') {
					url += '&stale_days=' + $('#stale_days').val();
				}
				if (rt == 'reconciliation') {
					url += '&subnet_id=' + $('#subnet_id').val();
				}
				document.location = url;
			}
			function exportPDF() {
				var rt = $('#report_type').val();
				var url = 'cereus_ipam_reports.php?action=export_pdf&report_type=' + rt;
				if (rt == 'utilization' || rt == 'states') {
					url += '&section_id=' + $('#section_id').val();
				}
				if (rt == 'utilization') {
					url += '&status_filter=' + $('#status_filter').val();
				}
				if (rt == 'stale') {
					url += '&stale_days=' + $('#stale_days').val();
				}
				if (rt == 'reconciliation') {
					url += '&subnet_id=' + $('#subnet_id').val();
				}
				window.open(url, '_blank');
			}
			$(function() {
				showReportFilters();
				$('#report_type').change(function() { showReportFilters(); applyFilter(); });
				$('#section_id, #status_filter, #stale_days, #subnet_id').change(function() { applyFilter(); });
				$('#go').click(function() { applyFilter(); });
				$('#clear').click(function() { loadPageNoHeader('cereus_ipam_reports.php?header=false&clear=1'); });
				$('#export_csv').click(function() { exportCSV(); });
				$('#export_pdf').click(function() { exportPDF(); });
				$('#send_report_now').click(function() {
					var btn = $(this);
					var res = $('#send_report_result');
					btn.prop('disabled', true).val('<?php print __esc('Sending...', 'cereus_ipam'); ?>');
					res.css('color', '#888').text('');
					$.post('cereus_ipam_reports.php', { action: 'send_now', __csrf_magic: csrfMagicToken })
						.done(function(data) {
							if (data.ok) {
								res.css('color', '#27ae60').text(data.message || '<?php print __esc('Sent.', 'cereus_ipam'); ?>');
							} else {
								res.css('color', '#e74c3c').text(data.error || '<?php print __esc('Failed.', 'cereus_ipam'); ?>');
							}
						})
						.fail(function() {
							res.css('color', '#e74c3c').text('<?php print __esc('Request failed.', 'cereus_ipam'); ?>');
						})
						.always(function() {
							btn.prop('disabled', false).val('<?php print __esc('Send Email Now', 'cereus_ipam'); ?>');
							setTimeout(function() { res.text(''); }, 8000);
						});
				});
			});
			</script>
		</td>
	</tr>
	<?php
	html_end_box();

	/* Render the selected report */
	switch ($report_type) {
		case 'utilization':
			cereus_ipam_report_utilization($section_id, $status_filter);
			break;
		case 'states':
			cereus_ipam_report_states($section_id);
			break;
		case 'stale':
			cereus_ipam_report_stale($stale_days);
			break;
		case 'reconciliation':
			cereus_ipam_report_reconciliation($subnet_id);
			break;
	}
}

/* ==================== Report: Subnet Utilization ==================== */

function cereus_ipam_report_utilization($section_id, $status_filter) {
	$sql_where  = 'WHERE 1=1';
	$sql_params = array();

	if ($section_id >= 0) {
		$sql_where .= ' AND s.section_id = ?';
		$sql_params[] = $section_id;
	}

	$subnets = db_fetch_assoc_prepared(
		"SELECT s.*, sec.name AS section_name
		FROM plugin_cereus_ipam_subnets s
		LEFT JOIN plugin_cereus_ipam_sections sec ON sec.id = s.section_id
		$sql_where
		ORDER BY s.subnet, s.mask",
		$sql_params
	);

	/* Build utilization data and sort by utilization descending */
	$rows = array();
	if (cacti_sizeof($subnets)) foreach ($subnets as $s) {
		$util = cereus_ipam_subnet_utilization($s['id']);
		$pct = $util['pct'];
		$threshold = isset($s['threshold_pct']) ? (int) $s['threshold_pct'] : 90;

		if ($pct >= 90) {
			$status = 'critical';
		} elseif ($pct >= 75) {
			$status = 'warning';
		} else {
			$status = 'ok';
		}

		/* Apply status filter */
		if ($status_filter !== 'all' && $status !== $status_filter) {
			continue;
		}

		$rows[] = array(
			'id'           => $s['id'],
			'cidr'         => $s['subnet'] . '/' . $s['mask'],
			'section_name' => $s['section_name'] ?? '',
			'description'  => $s['description'] ?? '',
			'used'         => $util['used'],
			'total'        => $util['total'],
			'pct'          => $pct,
			'threshold'    => $threshold,
			'status'       => $status,
		);
	}

	/* Sort by utilization descending */
	usort($rows, function ($a, $b) {
		return $b['pct'] <=> $a['pct'];
	});

	html_start_box(__('Subnet Utilization Report', 'cereus_ipam'), '100%', '', '3', 'center', '');

	$display_text = array(
		array('display' => __('Subnet / CIDR', 'cereus_ipam'),   'align' => 'left'),
		array('display' => __('Section', 'cereus_ipam'),         'align' => 'left'),
		array('display' => __('Description', 'cereus_ipam'),     'align' => 'left'),
		array('display' => __('Used IPs', 'cereus_ipam'),        'align' => 'right'),
		array('display' => __('Total IPs', 'cereus_ipam'),       'align' => 'right'),
		array('display' => __('Utilization', 'cereus_ipam'),     'align' => 'left'),
		array('display' => __('Threshold', 'cereus_ipam'),       'align' => 'center'),
		array('display' => __('Status', 'cereus_ipam'),          'align' => 'center'),
	);
	html_header($display_text);

	if (cacti_sizeof($rows)) {
		foreach ($rows as $row) {
			form_alternate_row('util_' . $row['id']);

			form_selectable_cell(
				'<a class="linkEditMain" href="cereus_ipam.php?action=edit&id=' . $row['id'] . '">' . html_escape($row['cidr']) . '</a>',
				$row['id']
			);
			form_selectable_cell(html_escape($row['section_name']), $row['id']);
			form_selectable_cell(html_escape($row['description']), $row['id']);
			form_selectable_cell(number_format_i18n($row['used']), $row['id'], '', 'right');
			form_selectable_cell(number_format_i18n($row['total']), $row['id'], '', 'right');
			form_selectable_cell(cereus_ipam_utilization_bar($row['pct']), $row['id']);
			form_selectable_cell($row['threshold'] . '%', $row['id'], '', 'center');

			$status_colors = array(
				'ok'       => '#4CAF50',
				'warning'  => '#FF9800',
				'critical' => '#F44336',
			);
			$status_labels = array(
				'ok'       => __('OK', 'cereus_ipam'),
				'warning'  => __('Warning', 'cereus_ipam'),
				'critical' => __('Critical', 'cereus_ipam'),
			);
			$sc = $status_colors[$row['status']] ?? '#9E9E9E';
			$sl = $status_labels[$row['status']] ?? $row['status'];
			form_selectable_cell('<span style="color:' . $sc . ';font-weight:bold;">' . $sl . '</span>', $row['id'], '', 'center');

			form_end_row();
		}
	} else {
		print '<tr><td colspan="8"><em>' . __('No subnets match the selected filters.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box();
}

/* ==================== Report: Address State Summary ==================== */

function cereus_ipam_report_states($section_id) {
	$sql_where  = 'WHERE 1=1';
	$sql_params = array();

	if ($section_id >= 0) {
		$sql_where .= ' AND s.section_id = ?';
		$sql_params[] = $section_id;
	}

	$subnets = db_fetch_assoc_prepared(
		"SELECT s.id, s.subnet, s.mask, s.description, sec.name AS section_name
		FROM plugin_cereus_ipam_subnets s
		LEFT JOIN plugin_cereus_ipam_sections sec ON sec.id = s.section_id
		$sql_where
		ORDER BY s.subnet, s.mask",
		$sql_params
	);

	/* Get state counts per subnet */
	$state_data = db_fetch_assoc("SELECT subnet_id, state, COUNT(*) AS cnt
		FROM plugin_cereus_ipam_addresses
		GROUP BY subnet_id, state");

	/* Build a lookup: subnet_id -> state -> count */
	$state_map = array();
	if (cacti_sizeof($state_data)) {
		foreach ($state_data as $sd) {
			$state_map[$sd['subnet_id']][$sd['state']] = (int) $sd['cnt'];
		}
	}

	$states = array('active', 'reserved', 'dhcp', 'offline', 'available');
	$state_colors = array(
		'active'    => '#4CAF50',
		'reserved'  => '#FF9800',
		'dhcp'      => '#2196F3',
		'offline'   => '#9E9E9E',
		'available' => '#E0E0E0',
	);

	html_start_box(__('Address State Summary', 'cereus_ipam'), '100%', '', '3', 'center', '');

	$display_text = array(
		array('display' => __('Subnet', 'cereus_ipam'),    'align' => 'left'),
		array('display' => __('Active', 'cereus_ipam'),    'align' => 'right'),
		array('display' => __('Reserved', 'cereus_ipam'),  'align' => 'right'),
		array('display' => __('DHCP', 'cereus_ipam'),      'align' => 'right'),
		array('display' => __('Offline', 'cereus_ipam'),   'align' => 'right'),
		array('display' => __('Available', 'cereus_ipam'), 'align' => 'right'),
		array('display' => __('Distribution', 'cereus_ipam'), 'align' => 'left'),
	);
	html_header($display_text);

	$totals = array('active' => 0, 'reserved' => 0, 'dhcp' => 0, 'offline' => 0, 'available' => 0);

	if (cacti_sizeof($subnets)) {
		foreach ($subnets as $s) {
			$sid = $s['id'];
			$counts = array();
			$row_total = 0;

			foreach ($states as $st) {
				$counts[$st] = isset($state_map[$sid][$st]) ? $state_map[$sid][$st] : 0;
				$totals[$st] += $counts[$st];
				$row_total += $counts[$st];
			}

			form_alternate_row('state_' . $sid);

			$cidr = $s['subnet'] . '/' . $s['mask'];
			form_selectable_cell(
				'<a class="linkEditMain" href="cereus_ipam_addresses.php?subnet_id=' . $sid . '">' . html_escape($cidr) . '</a>'
				. ' <span style="color:#888;font-size:11px;">' . html_escape($s['description'] ?? '') . '</span>',
				$sid
			);

			foreach ($states as $st) {
				form_selectable_cell($counts[$st], $sid, '', 'right');
			}

			/* Stacked bar */
			$bar_html = cereus_ipam_state_stacked_bar($counts, $row_total, $state_colors);
			form_selectable_cell($bar_html, $sid);

			form_end_row();
		}

		/* Totals row */
		$grand_total = array_sum($totals);
		print '<tr class="tableRow">';
		print '<td style="font-weight:bold;">' . __('Total', 'cereus_ipam') . '</td>';
		foreach ($states as $st) {
			print '<td style="text-align:right;font-weight:bold;">' . number_format_i18n($totals[$st]) . '</td>';
		}
		print '<td>' . cereus_ipam_state_stacked_bar($totals, $grand_total, $state_colors) . '</td>';
		print '</tr>';
	} else {
		print '<tr><td colspan="7"><em>' . __('No subnets match the selected filters.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box();
}

/**
 * Build a CSS stacked bar for state distribution.
 */
function cereus_ipam_state_stacked_bar($counts, $total, $colors) {
	if ($total <= 0) {
		return '<div style="width:200px;height:16px;background:#E0E0E0;border-radius:3px;"></div>';
	}

	$html = '<div style="width:200px;height:16px;display:flex;border-radius:3px;overflow:hidden;" title="';
	$title_parts = array();
	foreach ($counts as $st => $cnt) {
		$title_parts[] = ucfirst($st) . ': ' . $cnt;
	}
	$html .= html_escape(implode(', ', $title_parts)) . '">';

	foreach ($counts as $st => $cnt) {
		if ($cnt <= 0) {
			continue;
		}
		$pct = round(($cnt / $total) * 100, 1);
		$color = isset($colors[$st]) ? $colors[$st] : '#9E9E9E';
		$html .= '<div style="width:' . $pct . '%;background:' . $color . ';"></div>';
	}

	$html .= '</div>';
	return $html;
}

/* ==================== Report: Stale Addresses ==================== */

function cereus_ipam_report_stale($stale_days) {
	$stale_days = max(1, (int) $stale_days);
	$cutoff = date('Y-m-d H:i:s', strtotime("-{$stale_days} days"));

	$addresses = db_fetch_assoc_prepared(
		"SELECT a.*, s.subnet, s.mask, s.description AS subnet_desc,
			sec.name AS section_name
		FROM plugin_cereus_ipam_addresses a
		JOIN plugin_cereus_ipam_subnets s ON s.id = a.subnet_id
		LEFT JOIN plugin_cereus_ipam_sections sec ON sec.id = s.section_id
		WHERE a.state IN ('active', 'offline')
			AND (a.last_seen < ? OR a.last_seen IS NULL)
		ORDER BY a.last_seen ASC, a.ip",
		array($cutoff)
	);

	html_start_box(
		__('Stale Addresses (not seen in %d days)', $stale_days, 'cereus_ipam'),
		'100%', '', '3', 'center', ''
	);

	$display_text = array(
		array('display' => __('IP Address', 'cereus_ipam'),  'align' => 'left'),
		array('display' => __('Hostname', 'cereus_ipam'),    'align' => 'left'),
		array('display' => __('Subnet', 'cereus_ipam'),      'align' => 'left'),
		array('display' => __('State', 'cereus_ipam'),       'align' => 'center'),
		array('display' => __('Last Seen', 'cereus_ipam'),   'align' => 'left'),
		array('display' => __('Owner', 'cereus_ipam'),       'align' => 'left'),
		array('display' => __('Description', 'cereus_ipam'), 'align' => 'left'),
	);
	html_header($display_text);

	if (cacti_sizeof($addresses)) {
		foreach ($addresses as $a) {
			form_alternate_row('stale_' . $a['id']);

			form_selectable_cell(
				'<a class="linkEditMain" href="cereus_ipam_addresses.php?action=edit&id=' . $a['id'] . '">' . html_escape($a['ip']) . '</a>',
				$a['id']
			);
			form_selectable_cell(html_escape($a['hostname'] ?? ''), $a['id']);
			form_selectable_cell(
				'<a href="cereus_ipam_addresses.php?subnet_id=' . $a['subnet_id'] . '">'
				. html_escape($a['subnet'] . '/' . $a['mask']) . '</a>',
				$a['id']
			);

			$state_colors = array(
				'active'  => '#4CAF50',
				'offline' => '#9E9E9E',
			);
			$sc = $state_colors[$a['state']] ?? '#9E9E9E';
			form_selectable_cell('<span style="color:' . $sc . ';">' . html_escape(ucfirst($a['state'])) . '</span>', $a['id'], '', 'center');

			$last_seen = !empty($a['last_seen']) ? $a['last_seen'] : '<span style="color:#F44336;">' . __('Never', 'cereus_ipam') . '</span>';
			form_selectable_cell($last_seen, $a['id']);
			form_selectable_cell(html_escape($a['owner'] ?? ''), $a['id']);
			form_selectable_cell(html_escape($a['description'] ?? ''), $a['id']);

			form_end_row();
		}
	} else {
		print '<tr><td colspan="7"><em>' . __('No stale addresses found for the selected threshold.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box();
}

/* ==================== Report: Reconciliation ==================== */

function cereus_ipam_report_reconciliation($subnet_id) {
	if (empty($subnet_id)) {
		html_start_box(__('Reconciliation Report', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr class="even"><td style="padding:8px 15px;"><em>' . __('Please select a subnet from the filter above to view the reconciliation report.', 'cereus_ipam') . '</em></td></tr>';
		html_end_box();
		return;
	}

	$subnet_id = (int) $subnet_id;
	$subnet = db_fetch_row_prepared("SELECT s.*, sec.name AS section_name
		FROM plugin_cereus_ipam_subnets s
		LEFT JOIN plugin_cereus_ipam_sections sec ON sec.id = s.section_id
		WHERE s.id = ?",
		array($subnet_id));

	if (!cacti_sizeof($subnet)) {
		html_start_box(__('Reconciliation Report', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr class="even"><td style="padding:8px 15px;"><em>' . __('Subnet not found.', 'cereus_ipam') . '</em></td></tr>';
		html_end_box();
		return;
	}

	$cidr = $subnet['subnet'] . '/' . $subnet['mask'];

	/* Section A: Alive but not in IPAM */
	$alive_not_ipam = db_fetch_assoc_prepared(
		"SELECT sr.ip, sr.hostname, sr.mac_address, sr.scanned_at
		FROM plugin_cereus_ipam_scan_results sr
		LEFT JOIN plugin_cereus_ipam_addresses a ON a.subnet_id = sr.subnet_id AND a.ip = sr.ip
		WHERE sr.subnet_id = ? AND sr.is_alive = 1 AND a.id IS NULL
		ORDER BY INET_ATON(sr.ip)",
		array($subnet_id)
	);

	html_start_box(
		__('Reconciliation: %s', html_escape($cidr), 'cereus_ipam') . ' &mdash; '
		. __('Alive but Not in IPAM', 'cereus_ipam')
		. ' (' . cacti_sizeof($alive_not_ipam) . ')',
		'100%', '', '3', 'center', ''
	);

	$display_text = array(
		array('display' => __('IP Address', 'cereus_ipam'),  'align' => 'left'),
		array('display' => __('Scan Hostname', 'cereus_ipam'), 'align' => 'left'),
		array('display' => __('MAC Address', 'cereus_ipam'), 'align' => 'left'),
		array('display' => __('Scanned At', 'cereus_ipam'),  'align' => 'left'),
	);
	html_header($display_text);

	if (cacti_sizeof($alive_not_ipam)) {
		$i = 0;
		foreach ($alive_not_ipam as $r) {
			form_alternate_row('anip_' . $i);
			form_selectable_cell(html_escape($r['ip']), $i);
			form_selectable_cell(html_escape($r['hostname'] ?? ''), $i);
			form_selectable_cell(html_escape($r['mac_address'] ?? ''), $i);
			form_selectable_cell($r['scanned_at'] ?? '', $i);
			form_end_row();
			$i++;
		}
	} else {
		print '<tr><td colspan="4"><em>' . __('No discrepancies found. All alive hosts are tracked in IPAM.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box();

	/* Section B: In IPAM but not alive */
	$ipam_not_alive = db_fetch_assoc_prepared(
		"SELECT a.ip, a.hostname, a.state, a.last_seen, a.description
		FROM plugin_cereus_ipam_addresses a
		LEFT JOIN plugin_cereus_ipam_scan_results sr ON sr.subnet_id = a.subnet_id AND sr.ip = a.ip AND sr.is_alive = 1
		WHERE a.subnet_id = ? AND a.state = 'active' AND sr.id IS NULL
		ORDER BY INET_ATON(a.ip)",
		array($subnet_id)
	);

	html_start_box(
		__('Reconciliation: %s', html_escape($cidr), 'cereus_ipam') . ' &mdash; '
		. __('In IPAM but Not Alive', 'cereus_ipam')
		. ' (' . cacti_sizeof($ipam_not_alive) . ')',
		'100%', '', '3', 'center', ''
	);

	$display_text = array(
		array('display' => __('IP Address', 'cereus_ipam'),  'align' => 'left'),
		array('display' => __('IPAM Hostname', 'cereus_ipam'), 'align' => 'left'),
		array('display' => __('State', 'cereus_ipam'),       'align' => 'center'),
		array('display' => __('Last Seen', 'cereus_ipam'),   'align' => 'left'),
		array('display' => __('Description', 'cereus_ipam'), 'align' => 'left'),
	);
	html_header($display_text);

	if (cacti_sizeof($ipam_not_alive)) {
		$i = 0;
		foreach ($ipam_not_alive as $r) {
			form_alternate_row('ina_' . $i);
			form_selectable_cell(html_escape($r['ip']), $i);
			form_selectable_cell(html_escape($r['hostname'] ?? ''), $i);
			form_selectable_cell('<span style="color:#4CAF50;">' . html_escape(ucfirst($r['state'])) . '</span>', $i, '', 'center');
			form_selectable_cell($r['last_seen'] ?? '', $i);
			form_selectable_cell(html_escape($r['description'] ?? ''), $i);
			form_end_row();
			$i++;
		}
	} else {
		print '<tr><td colspan="5"><em>' . __('No discrepancies found. All active IPAM addresses were found alive.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box();

	/* Section C: Hostname mismatches */
	$hostname_mismatch = db_fetch_assoc_prepared(
		"SELECT a.ip, a.hostname AS ipam_hostname, sr.hostname AS scan_hostname, a.state, a.last_seen
		FROM plugin_cereus_ipam_addresses a
		JOIN plugin_cereus_ipam_scan_results sr ON sr.subnet_id = a.subnet_id AND sr.ip = a.ip
		WHERE a.subnet_id = ?
			AND sr.is_alive = 1
			AND sr.hostname IS NOT NULL
			AND sr.hostname != ''
			AND (a.hostname IS NULL OR a.hostname != sr.hostname)
		ORDER BY INET_ATON(a.ip)",
		array($subnet_id)
	);

	html_start_box(
		__('Reconciliation: %s', html_escape($cidr), 'cereus_ipam') . ' &mdash; '
		. __('Hostname Mismatches', 'cereus_ipam')
		. ' (' . cacti_sizeof($hostname_mismatch) . ')',
		'100%', '', '3', 'center', ''
	);

	$display_text = array(
		array('display' => __('IP Address', 'cereus_ipam'),     'align' => 'left'),
		array('display' => __('IPAM Hostname', 'cereus_ipam'),  'align' => 'left'),
		array('display' => __('Scan Hostname', 'cereus_ipam'),  'align' => 'left'),
		array('display' => __('State', 'cereus_ipam'),          'align' => 'center'),
		array('display' => __('Last Seen', 'cereus_ipam'),      'align' => 'left'),
	);
	html_header($display_text);

	if (cacti_sizeof($hostname_mismatch)) {
		$i = 0;
		foreach ($hostname_mismatch as $r) {
			form_alternate_row('hmm_' . $i);
			form_selectable_cell(html_escape($r['ip']), $i);
			form_selectable_cell(html_escape($r['ipam_hostname'] ?? ''), $i);
			form_selectable_cell('<span style="color:#FF9800;">' . html_escape($r['scan_hostname']) . '</span>', $i);
			form_selectable_cell(html_escape(ucfirst($r['state'])), $i, '', 'center');
			form_selectable_cell($r['last_seen'] ?? '', $i);
			form_end_row();
			$i++;
		}
	} else {
		print '<tr><td colspan="5"><em>' . __('No hostname mismatches found.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box();
}

/* ==================== CSV Export ==================== */

function cereus_ipam_report_export_csv() {
	/* License gate */
	if (!cereus_ipam_license_at_least('professional')) {
		header('Location: cereus_ipam_reports.php');
		exit;
	}

	$report_type   = get_nfilter_request_var('report_type', 'utilization');
	$section_id    = get_nfilter_request_var('section_id', '-1');
	$status_filter = get_nfilter_request_var('status_filter', 'all');
	$stale_days    = get_nfilter_request_var('stale_days', '90');
	$subnet_id     = get_nfilter_request_var('subnet_id', '');

	$filename = 'ipam_report_' . $report_type . '_' . date('Ymd_His') . '.csv';

	header('Content-Type: text/csv; charset=UTF-8');
	header('Content-Disposition: attachment; filename="' . $filename . '"');

	$fh = fopen('php://output', 'w');

	switch ($report_type) {
		case 'utilization':
			cereus_ipam_export_csv_utilization($fh, $section_id, $status_filter);
			break;
		case 'states':
			cereus_ipam_export_csv_states($fh, $section_id);
			break;
		case 'stale':
			cereus_ipam_export_csv_stale($fh, $stale_days);
			break;
		case 'reconciliation':
			cereus_ipam_export_csv_reconciliation($fh, $subnet_id);
			break;
	}

	fclose($fh);
	exit;
}

function cereus_ipam_export_csv_utilization($fh, $section_id, $status_filter) {
	fputcsv($fh, array('Subnet/CIDR', 'Section', 'Description', 'Used IPs', 'Total IPs', 'Utilization %', 'Threshold %', 'Status'));

	$sql_where  = 'WHERE 1=1';
	$sql_params = array();

	if ($section_id >= 0) {
		$sql_where .= ' AND s.section_id = ?';
		$sql_params[] = $section_id;
	}

	$subnets = db_fetch_assoc_prepared(
		"SELECT s.*, sec.name AS section_name
		FROM plugin_cereus_ipam_subnets s
		LEFT JOIN plugin_cereus_ipam_sections sec ON sec.id = s.section_id
		$sql_where
		ORDER BY s.subnet, s.mask",
		$sql_params
	);

	$rows = array();
	if (cacti_sizeof($subnets)) foreach ($subnets as $s) {
		$util = cereus_ipam_subnet_utilization($s['id']);
		$pct = $util['pct'];
		$threshold = isset($s['threshold_pct']) ? (int) $s['threshold_pct'] : 90;

		if ($pct >= 90) {
			$status = 'Critical';
		} elseif ($pct >= 75) {
			$status = 'Warning';
		} else {
			$status = 'OK';
		}

		if ($status_filter !== 'all' && strtolower($status) !== $status_filter) {
			continue;
		}

		$rows[] = array($pct, array(
			$s['subnet'] . '/' . $s['mask'],
			$s['section_name'] ?? '',
			$s['description'] ?? '',
			$util['used'],
			$util['total'],
			$pct,
			$threshold,
			$status,
		));
	}

	/* Sort by utilization descending */
	usort($rows, function ($a, $b) {
		return $b[0] <=> $a[0];
	});

	foreach ($rows as $row) {
		fputcsv($fh, $row[1]);
	}
}

function cereus_ipam_export_csv_states($fh, $section_id) {
	fputcsv($fh, array('Subnet', 'Active', 'Reserved', 'DHCP', 'Offline', 'Available'));

	$sql_where  = 'WHERE 1=1';
	$sql_params = array();

	if ($section_id >= 0) {
		$sql_where .= ' AND s.section_id = ?';
		$sql_params[] = $section_id;
	}

	$subnets = db_fetch_assoc_prepared(
		"SELECT s.id, s.subnet, s.mask
		FROM plugin_cereus_ipam_subnets s
		$sql_where
		ORDER BY s.subnet, s.mask",
		$sql_params
	);

	$state_data = db_fetch_assoc("SELECT subnet_id, state, COUNT(*) AS cnt
		FROM plugin_cereus_ipam_addresses
		GROUP BY subnet_id, state");

	$state_map = array();
	if (cacti_sizeof($state_data)) {
		foreach ($state_data as $sd) {
			$state_map[$sd['subnet_id']][$sd['state']] = (int) $sd['cnt'];
		}
	}

	$states = array('active', 'reserved', 'dhcp', 'offline', 'available');
	$totals = array('active' => 0, 'reserved' => 0, 'dhcp' => 0, 'offline' => 0, 'available' => 0);

	if (cacti_sizeof($subnets)) foreach ($subnets as $s) {
		$cidr = $s['subnet'] . '/' . $s['mask'];
		$row = array($cidr);

		foreach ($states as $st) {
			$cnt = isset($state_map[$s['id']][$st]) ? $state_map[$s['id']][$st] : 0;
			$row[] = $cnt;
			$totals[$st] += $cnt;
		}

		fputcsv($fh, $row);
	}

	/* Totals row */
	$total_row = array('TOTAL');
	foreach ($states as $st) {
		$total_row[] = $totals[$st];
	}
	fputcsv($fh, $total_row);
}

function cereus_ipam_export_csv_stale($fh, $stale_days) {
	fputcsv($fh, array('IP Address', 'Hostname', 'Subnet', 'State', 'Last Seen', 'Owner', 'Description'));

	$stale_days = max(1, (int) $stale_days);
	$cutoff = date('Y-m-d H:i:s', strtotime("-{$stale_days} days"));

	$addresses = db_fetch_assoc_prepared(
		"SELECT a.*, s.subnet, s.mask
		FROM plugin_cereus_ipam_addresses a
		JOIN plugin_cereus_ipam_subnets s ON s.id = a.subnet_id
		WHERE a.state IN ('active', 'offline')
			AND (a.last_seen < ? OR a.last_seen IS NULL)
		ORDER BY a.last_seen ASC, a.ip",
		array($cutoff)
	);

	foreach ($addresses as $a) {
		fputcsv($fh, array(
			$a['ip'],
			$a['hostname'] ?? '',
			$a['subnet'] . '/' . $a['mask'],
			ucfirst($a['state']),
			$a['last_seen'] ?? 'Never',
			$a['owner'] ?? '',
			$a['description'] ?? '',
		));
	}
}

function cereus_ipam_export_csv_reconciliation($fh, $subnet_id) {
	if (empty($subnet_id)) {
		fputcsv($fh, array('Error: No subnet selected'));
		return;
	}

	$subnet_id = (int) $subnet_id;
	$subnet = db_fetch_row_prepared("SELECT subnet, mask FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));

	if (!cacti_sizeof($subnet)) {
		fputcsv($fh, array('Error: Subnet not found'));
		return;
	}

	$cidr = $subnet['subnet'] . '/' . $subnet['mask'];

	/* Section A */
	fputcsv($fh, array('--- Alive but Not in IPAM (' . $cidr . ') ---'));
	fputcsv($fh, array('IP Address', 'Scan Hostname', 'MAC Address', 'Scanned At'));

	$alive_not_ipam = db_fetch_assoc_prepared(
		"SELECT sr.ip, sr.hostname, sr.mac_address, sr.scanned_at
		FROM plugin_cereus_ipam_scan_results sr
		LEFT JOIN plugin_cereus_ipam_addresses a ON a.subnet_id = sr.subnet_id AND a.ip = sr.ip
		WHERE sr.subnet_id = ? AND sr.is_alive = 1 AND a.id IS NULL
		ORDER BY INET_ATON(sr.ip)",
		array($subnet_id)
	);

	if (cacti_sizeof($alive_not_ipam)) foreach ($alive_not_ipam as $r) {
		fputcsv($fh, array($r['ip'], $r['hostname'] ?? '', $r['mac_address'] ?? '', $r['scanned_at'] ?? ''));
	}

	/* Section B */
	fputcsv($fh, array(''));
	fputcsv($fh, array('--- In IPAM but Not Alive (' . $cidr . ') ---'));
	fputcsv($fh, array('IP Address', 'IPAM Hostname', 'State', 'Last Seen', 'Description'));

	$ipam_not_alive = db_fetch_assoc_prepared(
		"SELECT a.ip, a.hostname, a.state, a.last_seen, a.description
		FROM plugin_cereus_ipam_addresses a
		LEFT JOIN plugin_cereus_ipam_scan_results sr ON sr.subnet_id = a.subnet_id AND sr.ip = a.ip AND sr.is_alive = 1
		WHERE a.subnet_id = ? AND a.state = 'active' AND sr.id IS NULL
		ORDER BY INET_ATON(a.ip)",
		array($subnet_id)
	);

	if (cacti_sizeof($ipam_not_alive)) foreach ($ipam_not_alive as $r) {
		fputcsv($fh, array($r['ip'], $r['hostname'] ?? '', ucfirst($r['state']), $r['last_seen'] ?? '', $r['description'] ?? ''));
	}

	/* Section C */
	fputcsv($fh, array(''));
	fputcsv($fh, array('--- Hostname Mismatches (' . $cidr . ') ---'));
	fputcsv($fh, array('IP Address', 'IPAM Hostname', 'Scan Hostname', 'State', 'Last Seen'));

	$hostname_mismatch = db_fetch_assoc_prepared(
		"SELECT a.ip, a.hostname AS ipam_hostname, sr.hostname AS scan_hostname, a.state, a.last_seen
		FROM plugin_cereus_ipam_addresses a
		JOIN plugin_cereus_ipam_scan_results sr ON sr.subnet_id = a.subnet_id AND sr.ip = a.ip
		WHERE a.subnet_id = ?
			AND sr.is_alive = 1
			AND sr.hostname IS NOT NULL
			AND sr.hostname != ''
			AND (a.hostname IS NULL OR a.hostname != sr.hostname)
		ORDER BY INET_ATON(a.ip)",
		array($subnet_id)
	);

	if (cacti_sizeof($hostname_mismatch)) foreach ($hostname_mismatch as $r) {
		fputcsv($fh, array($r['ip'], $r['ipam_hostname'] ?? '', $r['scan_hostname'], ucfirst($r['state']), $r['last_seen'] ?? ''));
	}
}

/* ==================== PDF Export (Print-optimized HTML) ==================== */

function cereus_ipam_report_export_pdf() {
	/* License gate */
	if (!cereus_ipam_license_at_least('professional')) {
		header('Location: cereus_ipam_reports.php');
		exit;
	}

	$report_type   = get_nfilter_request_var('report_type', 'utilization');
	$section_id    = get_nfilter_request_var('section_id', '-1');
	$status_filter = get_nfilter_request_var('status_filter', 'all');
	$stale_days    = get_nfilter_request_var('stale_days', '90');
	$subnet_id     = get_nfilter_request_var('subnet_id', '');

	$report_titles = array(
		'utilization'    => __('Subnet Utilization Report', 'cereus_ipam'),
		'states'         => __('Address State Summary', 'cereus_ipam'),
		'stale'          => __('Stale Addresses Report', 'cereus_ipam'),
		'reconciliation' => __('Reconciliation Report', 'cereus_ipam'),
	);

	$title = $report_titles[$report_type] ?? __('IPAM Report', 'cereus_ipam');

	/* Generate table data */
	$headers = array();
	$rows = array();

	switch ($report_type) {
		case 'utilization':
			cereus_ipam_pdf_data_utilization($headers, $rows, $section_id, $status_filter);
			break;
		case 'states':
			cereus_ipam_pdf_data_states($headers, $rows, $section_id);
			break;
		case 'stale':
			cereus_ipam_pdf_data_stale($headers, $rows, $stale_days);
			break;
		case 'reconciliation':
			cereus_ipam_pdf_data_reconciliation($headers, $rows, $subnet_id);
			break;
	}

	/* Output print-optimized HTML */
	header('Content-Type: text/html; charset=UTF-8');

	print '<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>' . html_escape($title) . ' - Cereus IPAM</title>
<style>
@media print {
	body { margin: 0; }
	.no-print { display: none !important; }
	table { page-break-inside: auto; }
	tr { page-break-inside: avoid; page-break-after: auto; }
}
body {
	font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
	font-size: 11px;
	color: #333;
	margin: 20px;
	line-height: 1.4;
}
h1 {
	font-size: 18px;
	margin: 0 0 5px 0;
	color: #1a1a1a;
}
.report-meta {
	color: #666;
	font-size: 10px;
	margin-bottom: 15px;
	border-bottom: 2px solid #333;
	padding-bottom: 8px;
}
table {
	width: 100%;
	border-collapse: collapse;
	margin-bottom: 20px;
}
th {
	background: #f0f0f0;
	border: 1px solid #ccc;
	padding: 5px 8px;
	text-align: left;
	font-size: 10px;
	font-weight: bold;
	white-space: nowrap;
}
td {
	border: 1px solid #ddd;
	padding: 4px 8px;
	font-size: 10px;
}
tr:nth-child(even) td {
	background: #f9f9f9;
}
.text-right { text-align: right; }
.text-center { text-align: center; }
.status-ok { color: #4CAF50; font-weight: bold; }
.status-warning { color: #FF9800; font-weight: bold; }
.status-critical { color: #F44336; font-weight: bold; }
.utilization-bar {
	display: inline-block;
	width: 80px;
	height: 12px;
	background: #e0e0e0;
	border-radius: 2px;
	overflow: hidden;
	vertical-align: middle;
}
.utilization-fill {
	height: 100%;
	border-radius: 2px;
}
.section-header {
	background: #e8e8e8;
	font-weight: bold;
	font-size: 11px;
	padding: 6px 8px;
}
.footer {
	margin-top: 20px;
	padding-top: 8px;
	border-top: 1px solid #ccc;
	font-size: 9px;
	color: #999;
}
.print-btn {
	padding: 8px 20px;
	background: #1976D2;
	color: white;
	border: none;
	border-radius: 4px;
	cursor: pointer;
	font-size: 13px;
	margin-bottom: 15px;
}
.print-btn:hover { background: #1565C0; }
</style>
</head>
<body>
<div class="no-print" style="margin-bottom:15px;">
	<button class="print-btn" onclick="window.print();">' . __('Print / Save as PDF', 'cereus_ipam') . '</button>
	<button class="print-btn" style="background:#666;" onclick="window.close();">' . __('Close', 'cereus_ipam') . '</button>
</div>
<h1>' . html_escape($title) . '</h1>
<div class="report-meta">
	' . __('Cereus IPAM', 'cereus_ipam') . ' &mdash; '
	. __('Generated: %s', date('Y-m-d H:i:s'), 'cereus_ipam')
	. '</div>';

	if (cacti_sizeof($headers) && cacti_sizeof($rows)) {
		print '<table>';
		print '<thead><tr>';
		foreach ($headers as $h) {
			$align = isset($h['align']) ? $h['align'] : 'left';
			$class = ($align === 'right') ? ' class="text-right"' : (($align === 'center') ? ' class="text-center"' : '');
			print '<th' . $class . '>' . html_escape($h['display']) . '</th>';
		}
		print '</tr></thead>';
		print '<tbody>';

		foreach ($rows as $row) {
			if (isset($row['_section_header'])) {
				print '<tr><td class="section-header" colspan="' . count($headers) . '">' . html_escape($row['_section_header']) . '</td></tr>';
				continue;
			}

			$cls = isset($row['_class']) ? ' class="' . $row['_class'] . '"' : '';
			print '<tr' . $cls . '>';
			foreach ($headers as $idx => $h) {
				$align = isset($h['align']) ? $h['align'] : 'left';
				$class = ($align === 'right') ? ' class="text-right"' : (($align === 'center') ? ' class="text-center"' : '');
				$val = isset($row[$idx]) ? $row[$idx] : '';
				print '<td' . $class . '>' . $val . '</td>';
			}
			print '</tr>';
		}

		print '</tbody></table>';
	} else {
		print '<p><em>' . __('No data available for the selected filters.', 'cereus_ipam') . '</em></p>';
	}

	print '<div class="footer">'
		. __('Cereus IPAM by Urban-Software.de', 'cereus_ipam') . ' &mdash; '
		. __('Page generated on %s', date('Y-m-d H:i:s'), 'cereus_ipam')
		. '</div>';

	print '</body></html>';
	exit;
}

/* ==================== PDF Data Generators ==================== */

function cereus_ipam_pdf_data_utilization(&$headers, &$rows, $section_id, $status_filter) {
	$headers = array(
		array('display' => __('Subnet / CIDR', 'cereus_ipam'),   'align' => 'left'),
		array('display' => __('Section', 'cereus_ipam'),         'align' => 'left'),
		array('display' => __('Description', 'cereus_ipam'),     'align' => 'left'),
		array('display' => __('Used', 'cereus_ipam'),            'align' => 'right'),
		array('display' => __('Total', 'cereus_ipam'),           'align' => 'right'),
		array('display' => __('Utilization', 'cereus_ipam'),     'align' => 'left'),
		array('display' => __('Threshold', 'cereus_ipam'),       'align' => 'center'),
		array('display' => __('Status', 'cereus_ipam'),          'align' => 'center'),
	);

	$sql_where  = 'WHERE 1=1';
	$sql_params = array();

	if ($section_id >= 0) {
		$sql_where .= ' AND s.section_id = ?';
		$sql_params[] = $section_id;
	}

	$subnets = db_fetch_assoc_prepared(
		"SELECT s.*, sec.name AS section_name
		FROM plugin_cereus_ipam_subnets s
		LEFT JOIN plugin_cereus_ipam_sections sec ON sec.id = s.section_id
		$sql_where
		ORDER BY s.subnet, s.mask",
		$sql_params
	);

	$data = array();
	if (cacti_sizeof($subnets)) foreach ($subnets as $s) {
		$util = cereus_ipam_subnet_utilization($s['id']);
		$pct = $util['pct'];
		$threshold = isset($s['threshold_pct']) ? (int) $s['threshold_pct'] : 90;

		if ($pct >= 90) {
			$status = 'critical';
		} elseif ($pct >= 75) {
			$status = 'warning';
		} else {
			$status = 'ok';
		}

		if ($status_filter !== 'all' && $status !== $status_filter) {
			continue;
		}

		$bar_color = ($pct >= 90) ? '#F44336' : (($pct >= 75) ? '#FF9800' : '#4CAF50');
		$bar_html = '<div class="utilization-bar"><div class="utilization-fill" style="width:' . $pct . '%;background:' . $bar_color . ';"></div></div> ' . $pct . '%';

		$status_labels = array('ok' => 'OK', 'warning' => 'Warning', 'critical' => 'Critical');
		$status_html = '<span class="status-' . $status . '">' . $status_labels[$status] . '</span>';

		$data[] = array(
			'pct' => $pct,
			'row' => array(
				html_escape($s['subnet'] . '/' . $s['mask']),
				html_escape($s['section_name'] ?? ''),
				html_escape($s['description'] ?? ''),
				number_format_i18n($util['used']),
				number_format_i18n($util['total']),
				$bar_html,
				$threshold . '%',
				$status_html,
			)
		);
	}

	usort($data, function ($a, $b) {
		return $b['pct'] <=> $a['pct'];
	});

	foreach ($data as $d) {
		$rows[] = $d['row'];
	}
}

function cereus_ipam_pdf_data_states(&$headers, &$rows, $section_id) {
	$headers = array(
		array('display' => __('Subnet', 'cereus_ipam'),    'align' => 'left'),
		array('display' => __('Active', 'cereus_ipam'),    'align' => 'right'),
		array('display' => __('Reserved', 'cereus_ipam'),  'align' => 'right'),
		array('display' => __('DHCP', 'cereus_ipam'),      'align' => 'right'),
		array('display' => __('Offline', 'cereus_ipam'),   'align' => 'right'),
		array('display' => __('Available', 'cereus_ipam'), 'align' => 'right'),
	);

	$sql_where  = 'WHERE 1=1';
	$sql_params = array();

	if ($section_id >= 0) {
		$sql_where .= ' AND s.section_id = ?';
		$sql_params[] = $section_id;
	}

	$subnets = db_fetch_assoc_prepared(
		"SELECT s.id, s.subnet, s.mask, s.description
		FROM plugin_cereus_ipam_subnets s
		$sql_where
		ORDER BY s.subnet, s.mask",
		$sql_params
	);

	$state_data = db_fetch_assoc("SELECT subnet_id, state, COUNT(*) AS cnt
		FROM plugin_cereus_ipam_addresses
		GROUP BY subnet_id, state");

	$state_map = array();
	if (cacti_sizeof($state_data)) {
		foreach ($state_data as $sd) {
			$state_map[$sd['subnet_id']][$sd['state']] = (int) $sd['cnt'];
		}
	}

	$states = array('active', 'reserved', 'dhcp', 'offline', 'available');
	$totals = array('active' => 0, 'reserved' => 0, 'dhcp' => 0, 'offline' => 0, 'available' => 0);

	if (cacti_sizeof($subnets)) foreach ($subnets as $s) {
		$cidr = $s['subnet'] . '/' . $s['mask'];
		$row = array(html_escape($cidr . ' ' . ($s['description'] ?? '')));

		foreach ($states as $st) {
			$cnt = isset($state_map[$s['id']][$st]) ? $state_map[$s['id']][$st] : 0;
			$row[] = $cnt;
			$totals[$st] += $cnt;
		}

		$rows[] = $row;
	}

	/* Totals row */
	$total_row = array('<strong>' . __('Total', 'cereus_ipam') . '</strong>');
	foreach ($states as $st) {
		$total_row[] = '<strong>' . number_format_i18n($totals[$st]) . '</strong>';
	}
	$rows[] = $total_row;
}

function cereus_ipam_pdf_data_stale(&$headers, &$rows, $stale_days) {
	$headers = array(
		array('display' => __('IP Address', 'cereus_ipam'),  'align' => 'left'),
		array('display' => __('Hostname', 'cereus_ipam'),    'align' => 'left'),
		array('display' => __('Subnet', 'cereus_ipam'),      'align' => 'left'),
		array('display' => __('State', 'cereus_ipam'),       'align' => 'center'),
		array('display' => __('Last Seen', 'cereus_ipam'),   'align' => 'left'),
		array('display' => __('Owner', 'cereus_ipam'),       'align' => 'left'),
		array('display' => __('Description', 'cereus_ipam'), 'align' => 'left'),
	);

	$stale_days = max(1, (int) $stale_days);
	$cutoff = date('Y-m-d H:i:s', strtotime("-{$stale_days} days"));

	$addresses = db_fetch_assoc_prepared(
		"SELECT a.*, s.subnet, s.mask
		FROM plugin_cereus_ipam_addresses a
		JOIN plugin_cereus_ipam_subnets s ON s.id = a.subnet_id
		WHERE a.state IN ('active', 'offline')
			AND (a.last_seen < ? OR a.last_seen IS NULL)
		ORDER BY a.last_seen ASC, a.ip",
		array($cutoff)
	);

	if (cacti_sizeof($addresses)) foreach ($addresses as $a) {
		$rows[] = array(
			html_escape($a['ip']),
			html_escape($a['hostname'] ?? ''),
			html_escape($a['subnet'] . '/' . $a['mask']),
			html_escape(ucfirst($a['state'])),
			!empty($a['last_seen']) ? $a['last_seen'] : __('Never', 'cereus_ipam'),
			html_escape($a['owner'] ?? ''),
			html_escape($a['description'] ?? ''),
		);
	}
}

function cereus_ipam_pdf_data_reconciliation(&$headers, &$rows, $subnet_id) {
	if (empty($subnet_id)) {
		return;
	}

	$subnet_id = (int) $subnet_id;
	$subnet = db_fetch_row_prepared("SELECT subnet, mask FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));

	if (!cacti_sizeof($subnet)) {
		return;
	}

	$cidr = $subnet['subnet'] . '/' . $subnet['mask'];

	$headers = array(
		array('display' => __('IP Address', 'cereus_ipam'),  'align' => 'left'),
		array('display' => __('Detail 1', 'cereus_ipam'),    'align' => 'left'),
		array('display' => __('Detail 2', 'cereus_ipam'),    'align' => 'left'),
		array('display' => __('Detail 3', 'cereus_ipam'),    'align' => 'left'),
		array('display' => __('Detail 4', 'cereus_ipam'),    'align' => 'left'),
	);

	/* Section A: Alive but not in IPAM */
	$alive_not_ipam = db_fetch_assoc_prepared(
		"SELECT sr.ip, sr.hostname, sr.mac_address, sr.scanned_at
		FROM plugin_cereus_ipam_scan_results sr
		LEFT JOIN plugin_cereus_ipam_addresses a ON a.subnet_id = sr.subnet_id AND a.ip = sr.ip
		WHERE sr.subnet_id = ? AND sr.is_alive = 1 AND a.id IS NULL
		ORDER BY INET_ATON(sr.ip)",
		array($subnet_id)
	);

	$rows[] = array('_section_header' => __('Alive but Not in IPAM', 'cereus_ipam') . ' (' . $cidr . ') - ' . cacti_sizeof($alive_not_ipam) . ' ' . __('found', 'cereus_ipam'));

	if (cacti_sizeof($alive_not_ipam)) foreach ($alive_not_ipam as $r) {
		$rows[] = array(
			html_escape($r['ip']),
			html_escape($r['hostname'] ?? ''),
			html_escape($r['mac_address'] ?? ''),
			$r['scanned_at'] ?? '',
			'',
		);
	}

	/* Section B: In IPAM but not alive */
	$ipam_not_alive = db_fetch_assoc_prepared(
		"SELECT a.ip, a.hostname, a.state, a.last_seen, a.description
		FROM plugin_cereus_ipam_addresses a
		LEFT JOIN plugin_cereus_ipam_scan_results sr ON sr.subnet_id = a.subnet_id AND sr.ip = a.ip AND sr.is_alive = 1
		WHERE a.subnet_id = ? AND a.state = 'active' AND sr.id IS NULL
		ORDER BY INET_ATON(a.ip)",
		array($subnet_id)
	);

	$rows[] = array('_section_header' => __('In IPAM but Not Alive', 'cereus_ipam') . ' (' . $cidr . ') - ' . cacti_sizeof($ipam_not_alive) . ' ' . __('found', 'cereus_ipam'));

	if (cacti_sizeof($ipam_not_alive)) foreach ($ipam_not_alive as $r) {
		$rows[] = array(
			html_escape($r['ip']),
			html_escape($r['hostname'] ?? ''),
			html_escape(ucfirst($r['state'])),
			$r['last_seen'] ?? '',
			html_escape($r['description'] ?? ''),
		);
	}

	/* Section C: Hostname mismatches */
	$hostname_mismatch = db_fetch_assoc_prepared(
		"SELECT a.ip, a.hostname AS ipam_hostname, sr.hostname AS scan_hostname, a.state, a.last_seen
		FROM plugin_cereus_ipam_addresses a
		JOIN plugin_cereus_ipam_scan_results sr ON sr.subnet_id = a.subnet_id AND sr.ip = a.ip
		WHERE a.subnet_id = ?
			AND sr.is_alive = 1
			AND sr.hostname IS NOT NULL
			AND sr.hostname != ''
			AND (a.hostname IS NULL OR a.hostname != sr.hostname)
		ORDER BY INET_ATON(a.ip)",
		array($subnet_id)
	);

	$rows[] = array('_section_header' => __('Hostname Mismatches', 'cereus_ipam') . ' (' . $cidr . ') - ' . cacti_sizeof($hostname_mismatch) . ' ' . __('found', 'cereus_ipam'));

	if (cacti_sizeof($hostname_mismatch)) foreach ($hostname_mismatch as $r) {
		$rows[] = array(
			html_escape($r['ip']),
			__('IPAM:', 'cereus_ipam') . ' ' . html_escape($r['ipam_hostname'] ?? ''),
			__('Scan:', 'cereus_ipam') . ' ' . html_escape($r['scan_hostname']),
			html_escape(ucfirst($r['state'])),
			$r['last_seen'] ?? '',
		);
	}
}

/* ==================== Send Report Now (AJAX) ==================== */

function cereus_ipam_report_send_now() {
	header('Content-Type: application/json; charset=utf-8');

	if (!cereus_ipam_license_at_least('professional')) {
		echo json_encode(array('ok' => false, 'error' => __('Professional license required.', 'cereus_ipam')));
		exit;
	}

	$manual_recipients = trim(read_config_option('cereus_ipam_report_recipients'));
	$notify_list_id    = (int) read_config_option('cereus_ipam_report_notify_list');
	$recipients        = cereus_ipam_merge_notification_emails($manual_recipients, $notify_list_id);

	if (empty($recipients)) {
		echo json_encode(array('ok' => false, 'error' => __('No recipients configured. Add email addresses in Settings → IPAM → Scheduled Reports.', 'cereus_ipam')));
		exit;
	}

	$report_types = array();
	if (read_config_option('cereus_ipam_report_inc_utilization') == 'on') $report_types[] = 'utilization';
	if (read_config_option('cereus_ipam_report_inc_states')      == 'on') $report_types[] = 'states';
	if (read_config_option('cereus_ipam_report_inc_stale')       == 'on') $report_types[] = 'stale';

	if (empty($report_types)) {
		/* Nothing ticked in settings — send all sections */
		$report_types = array('utilization', 'states', 'stale');
	}

	$success = cereus_ipam_send_scheduled_report($recipients, $report_types);

	if ($success) {
		cacti_log('CEREUS_IPAM: Manual report sent to ' . $recipients, false, 'CEREUS_IPAM');
		echo json_encode(array('ok' => true, 'message' => __('Report sent successfully.', 'cereus_ipam')));
	} else {
		echo json_encode(array('ok' => false, 'error' => __('Failed to send report. Check Cacti mail settings.', 'cereus_ipam')));
	}
	exit;
}
