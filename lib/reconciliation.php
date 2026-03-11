<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2024-2026 Urban-Software.de / Thomas Urban               |
 +-------------------------------------------------------------------------+
 | Cereus IPAM - Automated Reconciliation (Enterprise)                     |
 +-------------------------------------------------------------------------+
*/

/**
 * Reconcile a single subnet by comparing IPAM address records against the
 * latest scan results. Identifies discovered, stale, MAC-mismatched, and
 * hostname-mismatched entries.
 *
 * @param  int   $subnet_id  The subnet ID to reconcile
 * @return array              Reconciliation results with success flag and categorised arrays
 */
function cereus_ipam_reconcile_subnet($subnet_id) {
	$subnet_id = (int) $subnet_id;

	$subnet = db_fetch_row_prepared(
		"SELECT * FROM plugin_cereus_ipam_subnets WHERE id = ?",
		array($subnet_id)
	);

	if (!cacti_sizeof($subnet)) {
		return array('success' => false, 'error' => __('Subnet not found', 'cereus_ipam'));
	}

	/* Determine the latest scan batch timestamp for this subnet */
	$latest_scan = db_fetch_cell_prepared(
		"SELECT MAX(scanned_at) FROM plugin_cereus_ipam_scan_results WHERE subnet_id = ?",
		array($subnet_id)
	);

	if (empty($latest_scan)) {
		return array('success' => false, 'error' => __('No scan results available for this subnet', 'cereus_ipam'));
	}

	/* Fetch scan results from the latest batch (alive hosts only) */
	$scan_rows = db_fetch_assoc_prepared(
		"SELECT ip, hostname, mac_address, scan_type
		FROM plugin_cereus_ipam_scan_results
		WHERE subnet_id = ? AND scanned_at = ? AND is_alive = 1",
		array($subnet_id, $latest_scan)
	);

	/* Index scan results by IP for fast lookup */
	$scan_by_ip = array();
	foreach ($scan_rows as $sr) {
		$scan_by_ip[$sr['ip']] = $sr;
	}

	/* Fetch existing address records for this subnet */
	$addr_rows = db_fetch_assoc_prepared(
		"SELECT id, ip, hostname, mac_address, state, description, owner
		FROM plugin_cereus_ipam_addresses
		WHERE subnet_id = ?",
		array($subnet_id)
	);

	/* Index address records by IP for fast lookup */
	$addr_by_ip = array();
	foreach ($addr_rows as $ar) {
		$addr_by_ip[$ar['ip']] = $ar;
	}

	$discovered         = array();
	$stale              = array();
	$mac_mismatch       = array();
	$hostname_mismatch  = array();

	/* 1. Discovered: IPs in scan results but NOT in addresses table */
	foreach ($scan_by_ip as $ip => $scan) {
		if (!isset($addr_by_ip[$ip])) {
			$discovered[] = array(
				'ip'            => $ip,
				'scan_hostname' => $scan['hostname'] ?? '',
				'scan_mac'      => $scan['mac_address'] ?? '',
				'scan_type'     => $scan['scan_type'],
			);
		}
	}

	/* 2. Stale + MAC/Hostname mismatches: compare existing active addresses against scan */
	foreach ($addr_by_ip as $ip => $addr) {
		if ($addr['state'] === 'active') {
			if (!isset($scan_by_ip[$ip])) {
				/* Active address not found alive in latest scan */
				$stale[] = array(
					'ip'          => $ip,
					'address_id'  => $addr['id'],
					'hostname'    => $addr['hostname'] ?? '',
					'mac_address' => $addr['mac_address'] ?? '',
					'state'       => $addr['state'],
					'owner'       => $addr['owner'] ?? '',
				);
			}
		}

		/* MAC and hostname mismatches only apply when the IP appears in both tables */
		if (isset($scan_by_ip[$ip])) {
			$scan = $scan_by_ip[$ip];

			/* 3. MAC mismatch: both sides have a MAC and they differ */
			$addr_mac = strtoupper(trim($addr['mac_address'] ?? ''));
			$scan_mac = strtoupper(trim($scan['mac_address'] ?? ''));

			if ($addr_mac !== '' && $scan_mac !== '' && $addr_mac !== $scan_mac) {
				$mac_mismatch[] = array(
					'ip'          => $ip,
					'address_id'  => $addr['id'],
					'hostname'    => $addr['hostname'] ?? '',
					'mac_address' => $addr_mac,
					'scan_mac'    => $scan_mac,
					'state'       => $addr['state'],
				);
			}

			/* 4. Hostname mismatch: both sides have a hostname and they differ */
			$addr_host = strtolower(trim($addr['hostname'] ?? ''));
			$scan_host = strtolower(trim($scan['hostname'] ?? ''));

			if ($addr_host !== '' && $scan_host !== '' && $addr_host !== $scan_host) {
				$hostname_mismatch[] = array(
					'ip'            => $ip,
					'address_id'    => $addr['id'],
					'hostname'      => $addr['hostname'] ?? '',
					'scan_hostname' => $scan['hostname'] ?? '',
					'state'         => $addr['state'],
				);
			}
		}
	}

	$summary = array(
		'subnet_id'          => $subnet_id,
		'subnet'             => $subnet['subnet'] . '/' . $subnet['mask'],
		'description'        => $subnet['description'] ?? '',
		'scan_time'          => $latest_scan,
		'total_scan_alive'   => count($scan_by_ip),
		'total_addresses'    => count($addr_by_ip),
		'discovered_count'   => count($discovered),
		'stale_count'        => count($stale),
		'mac_mismatch_count' => count($mac_mismatch),
		'hostname_mismatch_count' => count($hostname_mismatch),
	);

	return array(
		'success'            => true,
		'discovered'         => $discovered,
		'stale'              => $stale,
		'mac_mismatch'       => $mac_mismatch,
		'hostname_mismatch'  => $hostname_mismatch,
		'summary'            => $summary,
	);
}

/**
 * Run reconciliation for all subnets that have been scanned.
 * Called from the poller. Requires Enterprise license.
 *
 * Aggregates per-subnet results and optionally sends an email summary
 * when significant discrepancies are found.
 *
 * @return array  Aggregated results across all subnets
 */
function cereus_ipam_reconcile_all() {
	if (!cereus_ipam_license_has_reconciliation()) {
		cacti_log('CEREUS_IPAM RECONCILE: Skipped - Enterprise license required', false, 'PLUGIN');
		return array('success' => false, 'error' => __('Enterprise license required for automated reconciliation', 'cereus_ipam'));
	}

	/* Check maintenance window suppression globally */
	if (function_exists('cereus_ipam_is_in_maintenance') && cereus_ipam_is_in_maintenance()) {
		cacti_log('CEREUS_IPAM RECONCILE: Skipped - maintenance window active', false, 'PLUGIN');
		return array('success' => false, 'error' => __('Reconciliation suppressed during maintenance', 'cereus_ipam'));
	}

	$subnets = db_fetch_assoc("SELECT id, subnet, mask, description
		FROM plugin_cereus_ipam_subnets
		WHERE last_scanned IS NOT NULL
		ORDER BY subnet, mask");

	if (!cacti_sizeof($subnets)) {
		cacti_log('CEREUS_IPAM RECONCILE: No scanned subnets found', false, 'PLUGIN');
		return array('success' => true, 'subnets_processed' => 0, 'results' => array());
	}

	$all_results   = array();
	$total_discovered  = 0;
	$total_stale       = 0;
	$total_mac         = 0;
	$total_hostname    = 0;
	$subnets_processed = 0;

	foreach ($subnets as $subnet) {
		/* Skip subnets under maintenance */
		if (function_exists('cereus_ipam_should_suppress_scan') && cereus_ipam_should_suppress_scan($subnet['id'])) {
			continue;
		}

		$result = cereus_ipam_reconcile_subnet($subnet['id']);

		if ($result['success']) {
			$all_results[] = $result;
			$subnets_processed++;

			$total_discovered += count($result['discovered']);
			$total_stale      += count($result['stale']);
			$total_mac        += count($result['mac_mismatch']);
			$total_hostname   += count($result['hostname_mismatch']);

			$cidr = $subnet['subnet'] . '/' . $subnet['mask'];
			cacti_log(
				'CEREUS_IPAM RECONCILE: Subnet ' . $cidr
				. ' - Discovered: ' . count($result['discovered'])
				. ', Stale: ' . count($result['stale'])
				. ', MAC mismatch: ' . count($result['mac_mismatch'])
				. ', Hostname mismatch: ' . count($result['hostname_mismatch']),
				false, 'PLUGIN'
			);
		}
	}

	$total_discrepancies = $total_discovered + $total_stale + $total_mac + $total_hostname;

	cacti_log(
		'CEREUS_IPAM RECONCILE: Completed - '
		. $subnets_processed . ' subnets, '
		. $total_discrepancies . ' total discrepancies '
		. '(discovered: ' . $total_discovered
		. ', stale: ' . $total_stale
		. ', mac: ' . $total_mac
		. ', hostname: ' . $total_hostname . ')',
		false, 'PLUGIN'
	);

	/* Store last run timestamp */
	set_config_option('cereus_ipam_reconcile_last_run', (string) time());

	/* Send email summary if threshold alerts are enabled and discrepancies exist */
	$notify_enabled = read_config_option('cereus_ipam_reconcile_notify');

	if ($notify_enabled == 'on' && $total_discrepancies > 0) {
		cereus_ipam_reconcile_send_summary($all_results, $total_discovered, $total_stale, $total_mac, $total_hostname);
	}

	return array(
		'success'            => true,
		'subnets_processed'  => $subnets_processed,
		'total_discovered'   => $total_discovered,
		'total_stale'        => $total_stale,
		'total_mac_mismatch' => $total_mac,
		'total_hostname_mismatch' => $total_hostname,
		'results'            => $all_results,
	);
}

/**
 * Send an email summary of reconciliation discrepancies.
 *
 * @param array $all_results       Array of per-subnet reconciliation results
 * @param int   $total_discovered  Total discovered count
 * @param int   $total_stale       Total stale count
 * @param int   $total_mac         Total MAC mismatch count
 * @param int   $total_hostname    Total hostname mismatch count
 */
function cereus_ipam_reconcile_send_summary($all_results, $total_discovered, $total_stale, $total_mac, $total_hostname) {
	$emails = read_config_option('cereus_ipam_threshold_emails');
	if (empty($emails)) {
		cacti_log('CEREUS_IPAM RECONCILE: Email summary skipped - no recipient emails configured', false, 'PLUGIN');
		return;
	}

	$total = $total_discovered + $total_stale + $total_mac + $total_hostname;
	$subject = '[Cereus IPAM] Reconciliation Summary: ' . $total . ' discrepancies found';

	/* Build HTML body */
	$body  = '<html><body style="font-family: Arial, Helvetica, sans-serif; font-size: 14px; color: #333;">';
	$body .= '<h2 style="color: #2c3e50;">IPAM Reconciliation Summary</h2>';
	$body .= '<p>' . html_escape(__('The automated reconciliation engine found the following discrepancies:', 'cereus_ipam')) . '</p>';

	/* Totals table */
	$body .= '<table cellpadding="8" cellspacing="0" border="0" style="border-collapse: collapse; min-width: 400px; margin: 15px 0;">';
	$body .= '<tr style="background-color: #f8f9fa; border-bottom: 1px solid #dee2e6;">';
	$body .= '<td style="font-weight: bold; padding: 8px 12px; border: 1px solid #dee2e6;">' . html_escape(__('Discovered (New)', 'cereus_ipam')) . '</td>';
	$body .= '<td style="padding: 8px 12px; border: 1px solid #dee2e6;">' . (int) $total_discovered . '</td></tr>';
	$body .= '<tr style="border-bottom: 1px solid #dee2e6;">';
	$body .= '<td style="font-weight: bold; padding: 8px 12px; border: 1px solid #dee2e6;">' . html_escape(__('Stale (Offline)', 'cereus_ipam')) . '</td>';
	$body .= '<td style="padding: 8px 12px; border: 1px solid #dee2e6;">' . (int) $total_stale . '</td></tr>';
	$body .= '<tr style="background-color: #f8f9fa; border-bottom: 1px solid #dee2e6;">';
	$body .= '<td style="font-weight: bold; padding: 8px 12px; border: 1px solid #dee2e6;">' . html_escape(__('MAC Mismatch', 'cereus_ipam')) . '</td>';
	$body .= '<td style="padding: 8px 12px; border: 1px solid #dee2e6;">' . (int) $total_mac . '</td></tr>';
	$body .= '<tr style="border-bottom: 1px solid #dee2e6;">';
	$body .= '<td style="font-weight: bold; padding: 8px 12px; border: 1px solid #dee2e6;">' . html_escape(__('Hostname Mismatch', 'cereus_ipam')) . '</td>';
	$body .= '<td style="padding: 8px 12px; border: 1px solid #dee2e6;">' . (int) $total_hostname . '</td></tr>';
	$body .= '</table>';

	/* Per-subnet details */
	$body .= '<h3 style="color: #2c3e50; margin-top: 20px;">' . html_escape(__('Per-Subnet Details', 'cereus_ipam')) . '</h3>';

	foreach ($all_results as $result) {
		$s = $result['summary'];
		$disc = $s['discovered_count'] + $s['stale_count'] + $s['mac_mismatch_count'] + $s['hostname_mismatch_count'];

		if ($disc == 0) {
			continue;
		}

		$body .= '<p style="margin: 10px 0 5px 0;"><strong>' . html_escape($s['subnet']) . '</strong>';
		if (!empty($s['description'])) {
			$body .= ' (' . html_escape($s['description']) . ')';
		}
		$body .= ' &mdash; ';
		$body .= html_escape(__('Discovered', 'cereus_ipam')) . ': ' . (int) $s['discovered_count'] . ', ';
		$body .= html_escape(__('Stale', 'cereus_ipam')) . ': ' . (int) $s['stale_count'] . ', ';
		$body .= html_escape(__('MAC', 'cereus_ipam')) . ': ' . (int) $s['mac_mismatch_count'] . ', ';
		$body .= html_escape(__('Hostname', 'cereus_ipam')) . ': ' . (int) $s['hostname_mismatch_count'];
		$body .= '</p>';
	}

	$body .= '<p style="font-size: 12px; color: #888; margin-top: 20px;">' . html_escape(__('This report was generated by the Cereus IPAM reconciliation engine.', 'cereus_ipam')) . '</p>';
	$body .= '</body></html>';

	/* Plain text version */
	$body_text  = __('IPAM Reconciliation Summary', 'cereus_ipam') . "\n";
	$body_text .= "=============================\n\n";
	$body_text .= __('Discovered (New)', 'cereus_ipam') . ': ' . $total_discovered . "\n";
	$body_text .= __('Stale (Offline)', 'cereus_ipam') . ': ' . $total_stale . "\n";
	$body_text .= __('MAC Mismatch', 'cereus_ipam') . ': ' . $total_mac . "\n";
	$body_text .= __('Hostname Mismatch', 'cereus_ipam') . ': ' . $total_hostname . "\n\n";

	foreach ($all_results as $result) {
		$s = $result['summary'];
		$disc = $s['discovered_count'] + $s['stale_count'] + $s['mac_mismatch_count'] + $s['hostname_mismatch_count'];

		if ($disc == 0) {
			continue;
		}

		$body_text .= $s['subnet'];
		if (!empty($s['description'])) {
			$body_text .= ' (' . $s['description'] . ')';
		}
		$body_text .= "\n";
		$body_text .= '  ' . __('Discovered', 'cereus_ipam') . ': ' . $s['discovered_count'];
		$body_text .= ', ' . __('Stale', 'cereus_ipam') . ': ' . $s['stale_count'];
		$body_text .= ', ' . __('MAC', 'cereus_ipam') . ': ' . $s['mac_mismatch_count'];
		$body_text .= ', ' . __('Hostname', 'cereus_ipam') . ': ' . $s['hostname_mismatch_count'];
		$body_text .= "\n\n";
	}

	$body_text .= "-- \n" . __('Generated by Cereus IPAM reconciliation engine.', 'cereus_ipam') . "\n";

	$error = mailer(
		'',         /* from - uses Cacti default */
		$emails,    /* to */
		'',         /* cc */
		'',         /* bcc */
		'',         /* replyto */
		$subject,   /* subject */
		$body,      /* body (HTML) */
		$body_text, /* body_text (plain) */
		array(),    /* attachments */
		array(),    /* headers */
		true        /* html */
	);

	if ($error == '') {
		cacti_log('CEREUS_IPAM RECONCILE: Email summary sent successfully', false, 'PLUGIN');
	} else {
		cacti_log('CEREUS_IPAM RECONCILE: Mailer error: ' . $error, false, 'PLUGIN');
	}
}

/**
 * Apply automated fixes for reconciliation discrepancies.
 *
 * @param  int    $subnet_id  The subnet ID to fix
 * @param  string $fix_type   One of: mark_stale, update_mac, add_discovered
 * @return array               Result with success flag and count of fixed items
 */
function cereus_ipam_reconcile_auto_fix($subnet_id, $fix_type) {
	$subnet_id = (int) $subnet_id;

	if (!cereus_ipam_license_has_reconciliation()) {
		return array('success' => false, 'error' => __('Enterprise license required', 'cereus_ipam'));
	}

	/* First run reconciliation to get current state */
	$recon = cereus_ipam_reconcile_subnet($subnet_id);

	if (!$recon['success']) {
		return array('success' => false, 'error' => $recon['error']);
	}

	$fixed = 0;

	switch ($fix_type) {
		case 'mark_stale':
			/* Set stale addresses (active but not seen in latest scan) to state='offline' */
			foreach ($recon['stale'] as $entry) {
				$old_row = db_fetch_row_prepared(
					"SELECT * FROM plugin_cereus_ipam_addresses WHERE id = ?",
					array($entry['address_id'])
				);

				if (cacti_sizeof($old_row) && $old_row['state'] === 'active') {
					db_execute_prepared(
						"UPDATE plugin_cereus_ipam_addresses SET state = 'offline' WHERE id = ?",
						array($entry['address_id'])
					);

					cereus_ipam_changelog_record(
						'update',
						'address',
						$entry['address_id'],
						array('state' => 'active'),
						array('state' => 'offline', 'reason' => 'reconciliation_stale')
					);

					$fixed++;
				}
			}

			cacti_log(
				'CEREUS_IPAM RECONCILE: mark_stale applied to subnet ' . $subnet_id . ' - ' . $fixed . ' addresses set to offline',
				false, 'PLUGIN'
			);
			break;

		case 'update_mac':
			/* Update MAC addresses from scan results where they differ */
			foreach ($recon['mac_mismatch'] as $entry) {
				$old_row = db_fetch_row_prepared(
					"SELECT * FROM plugin_cereus_ipam_addresses WHERE id = ?",
					array($entry['address_id'])
				);

				if (cacti_sizeof($old_row)) {
					db_execute_prepared(
						"UPDATE plugin_cereus_ipam_addresses SET mac_address = ? WHERE id = ?",
						array($entry['scan_mac'], $entry['address_id'])
					);

					cereus_ipam_changelog_record(
						'update',
						'address',
						$entry['address_id'],
						array('mac_address' => $entry['mac_address']),
						array('mac_address' => $entry['scan_mac'], 'reason' => 'reconciliation_mac_update')
					);

					$fixed++;
				}
			}

			cacti_log(
				'CEREUS_IPAM RECONCILE: update_mac applied to subnet ' . $subnet_id . ' - ' . $fixed . ' MAC addresses updated',
				false, 'PLUGIN'
			);
			break;

		case 'add_discovered':
			/* Add discovered IPs as new address records with state='active' */
			foreach ($recon['discovered'] as $entry) {
				/* Verify the address does not already exist (race condition guard) */
				$existing = db_fetch_cell_prepared(
					"SELECT COUNT(*) FROM plugin_cereus_ipam_addresses WHERE subnet_id = ? AND ip = ?",
					array($subnet_id, $entry['ip'])
				);

				if ((int) $existing > 0) {
					continue;
				}

				db_execute_prepared(
					"INSERT INTO plugin_cereus_ipam_addresses
						(subnet_id, ip, hostname, mac_address, state, last_seen, created_by)
					VALUES (?, ?, ?, ?, 'active', NOW(), 0)",
					array(
						$subnet_id,
						$entry['ip'],
						!empty($entry['scan_hostname']) ? $entry['scan_hostname'] : null,
						!empty($entry['scan_mac']) ? $entry['scan_mac'] : null,
					)
				);

				$new_id = db_fetch_insert_id();

				if ($new_id > 0) {
					cereus_ipam_changelog_record(
						'create',
						'address',
						$new_id,
						null,
						array(
							'ip'       => $entry['ip'],
							'hostname' => $entry['scan_hostname'] ?? '',
							'mac'      => $entry['scan_mac'] ?? '',
							'reason'   => 'reconciliation_discovered',
						)
					);

					$fixed++;
				}
			}

			cacti_log(
				'CEREUS_IPAM RECONCILE: add_discovered applied to subnet ' . $subnet_id . ' - ' . $fixed . ' addresses added',
				false, 'PLUGIN'
			);
			break;

		default:
			return array('success' => false, 'error' => __('Invalid fix type: %s', $fix_type, 'cereus_ipam'));
	}

	return array('success' => true, 'fixed' => $fixed);
}

/**
 * Get a summary of the last reconciliation across all subnets.
 * Returns an array of per-subnet summaries with discrepancy counts.
 * Used to display reconciliation status on the main IPAM page.
 *
 * @return array  Array of per-subnet reconciliation summaries
 */
function cereus_ipam_reconcile_summary() {
	if (!cereus_ipam_license_has_reconciliation()) {
		return array();
	}

	$subnets = db_fetch_assoc("SELECT id, subnet, mask, description, last_scanned
		FROM plugin_cereus_ipam_subnets
		WHERE last_scanned IS NOT NULL
		ORDER BY subnet, mask");

	if (!cacti_sizeof($subnets)) {
		return array();
	}

	$summaries = array();

	foreach ($subnets as $subnet) {
		$result = cereus_ipam_reconcile_subnet($subnet['id']);

		if (!$result['success']) {
			continue;
		}

		$s = $result['summary'];

		$total_discrepancies = $s['discovered_count'] + $s['stale_count']
			+ $s['mac_mismatch_count'] + $s['hostname_mismatch_count'];

		/* Determine severity based on discrepancy counts */
		if ($total_discrepancies == 0) {
			$severity = 'ok';
		} elseif ($total_discrepancies <= 5) {
			$severity = 'low';
		} elseif ($total_discrepancies <= 20) {
			$severity = 'medium';
		} else {
			$severity = 'high';
		}

		$summaries[] = array(
			'subnet_id'              => $subnet['id'],
			'subnet'                 => $subnet['subnet'] . '/' . $subnet['mask'],
			'description'            => $subnet['description'] ?? '',
			'last_scanned'           => $subnet['last_scanned'],
			'scan_time'              => $s['scan_time'],
			'total_scan_alive'       => $s['total_scan_alive'],
			'total_addresses'        => $s['total_addresses'],
			'discovered_count'       => $s['discovered_count'],
			'stale_count'            => $s['stale_count'],
			'mac_mismatch_count'     => $s['mac_mismatch_count'],
			'hostname_mismatch_count' => $s['hostname_mismatch_count'],
			'total_discrepancies'    => $total_discrepancies,
			'severity'               => $severity,
		);
	}

	/* Sort by total discrepancies descending (most problematic first) */
	usort($summaries, function ($a, $b) {
		return $b['total_discrepancies'] - $a['total_discrepancies'];
	});

	return $summaries;
}
