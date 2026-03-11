<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2024-2026 Urban-Software.de / Thomas Urban               |
 +-------------------------------------------------------------------------+
 | Cereus IPAM - Threshold Alerts                                          |
 +-------------------------------------------------------------------------+
*/

/**
 * Main threshold check function, called from poller_bottom hook.
 * Evaluates all subnets with a threshold configured and sends
 * email alerts when utilization meets or exceeds the threshold,
 * subject to a per-subnet cooldown period.
 */
function cereus_ipam_check_thresholds() {
	/* Check if threshold alerting is enabled in settings */
	$enabled = read_config_option('cereus_ipam_threshold_enabled');
	if (empty($enabled)) {
		return;
	}

	/* Check license permits threshold alerts */
	if (!cereus_ipam_license_has_threshold_alerts()) {
		return;
	}

	/* Get the cooldown period (seconds between repeated alerts for same subnet) */
	$cooldown = read_config_option('cereus_ipam_threshold_cooldown');
	if ($cooldown === '' || $cooldown === false || $cooldown === null) {
		$cooldown = 86400;
	}
	$cooldown = (int) $cooldown;

	/* Fetch all subnets that have a threshold set (threshold_pct > 0) */
	$subnets = db_fetch_assoc("SELECT * FROM plugin_cereus_ipam_subnets
		WHERE threshold_pct > 0
		ORDER BY subnet, mask");

	if (!cacti_sizeof($subnets)) {
		return;
	}

	$now = time();

	foreach ($subnets as $subnet) {
		$utilization = cereus_ipam_subnet_utilization($subnet['id']);

		/* Check if utilization meets or exceeds threshold */
		if ($utilization['pct'] >= $subnet['threshold_pct']) {
			/* Check cooldown: when was the last alert sent for this subnet? */
			$last_alert_key = 'cereus_ipam_threshold_last_' . $subnet['id'];
			$last_alert     = read_config_option($last_alert_key);

			if (!empty($last_alert) && ($now - (int) $last_alert) < $cooldown) {
				/* Still within cooldown window, skip */
				continue;
			}

			/* Check maintenance window suppression */
			if (function_exists('cereus_ipam_should_suppress_alert') && cereus_ipam_should_suppress_alert($subnet['id'])) {
				continue;
			}

			/* Send the alert */
			$result = cereus_ipam_send_threshold_alert($subnet, $utilization);

			if ($result) {
				/* Update last alert timestamp */
				set_config_option($last_alert_key, (string) $now);

				cacti_log(
					'CEREUS IPAM: Threshold alert sent for subnet ' .
					$subnet['subnet'] . '/' . $subnet['mask'] .
					' at ' . $utilization['pct'] . '% (threshold: ' . $subnet['threshold_pct'] . '%)',
					false, 'PLUGIN'
				);
			} else {
				cacti_log(
					'CEREUS IPAM WARNING: Failed to send threshold alert for subnet ' .
					$subnet['subnet'] . '/' . $subnet['mask'],
					false, 'PLUGIN'
				);
			}
		}
	}
}

/**
 * Send a threshold alert email for a subnet.
 *
 * @param array $subnet      Full row from plugin_cereus_ipam_subnets
 * @param array $utilization Array from cereus_ipam_subnet_utilization() with keys: used, free, total, pct
 * @return bool              True if mailer returned successfully
 */
function cereus_ipam_send_threshold_alert($subnet, $utilization) {
	/* Get recipient email addresses — merge manual emails with notification list */
	$manual_emails  = read_config_option('cereus_ipam_threshold_emails');
	$notify_list_id = (int) read_config_option('cereus_ipam_threshold_notify_list');
	$emails         = cereus_ipam_merge_notification_emails($manual_emails, $notify_list_id);
	if (empty($emails)) {
		cacti_log('CEREUS IPAM WARNING: Threshold alert triggered but no recipient emails configured', false, 'PLUGIN');
		return false;
	}

	$subnet_cidr = html_escape($subnet['subnet'] . '/' . $subnet['mask']);
	$description = html_escape($subnet['description'] ?? '');
	$gateway     = html_escape($subnet['gateway'] ?? '');
	$pct         = (int) $utilization['pct'];
	$used        = (int) $utilization['used'];
	$total       = (int) $utilization['total'];
	$free        = (int) $utilization['free'];
	$threshold   = (int) $subnet['threshold_pct'];

	/* Build email subject */
	$subject = '[Cereus IPAM] Subnet utilization alert: ' . $subnet['subnet'] . '/' . $subnet['mask'] . ' at ' . $pct . '%';

	/* Determine bar color based on severity */
	if ($pct >= 95) {
		$bar_color = '#e74c3c';
	} elseif ($pct >= 90) {
		$bar_color = '#e67e22';
	} else {
		$bar_color = '#f39c12';
	}

	/* Build HTML email body */
	$body = '<html><body style="font-family: Arial, Helvetica, sans-serif; font-size: 14px; color: #333;">';
	$body .= '<h2 style="color: #c0392b;">Subnet Utilization Alert</h2>';
	$body .= '<p>The following subnet has reached or exceeded its utilization threshold:</p>';

	$body .= '<table cellpadding="8" cellspacing="0" border="0" style="border-collapse: collapse; min-width: 400px; margin: 15px 0;">';

	$body .= '<tr style="background-color: #f8f9fa; border-bottom: 1px solid #dee2e6;">';
	$body .= '<td style="font-weight: bold; padding: 8px 12px; border: 1px solid #dee2e6;">Subnet</td>';
	$body .= '<td style="padding: 8px 12px; border: 1px solid #dee2e6;">' . $subnet_cidr . '</td>';
	$body .= '</tr>';

	$body .= '<tr style="border-bottom: 1px solid #dee2e6;">';
	$body .= '<td style="font-weight: bold; padding: 8px 12px; border: 1px solid #dee2e6;">Description</td>';
	$body .= '<td style="padding: 8px 12px; border: 1px solid #dee2e6;">' . ($description !== '' ? $description : '<em>None</em>') . '</td>';
	$body .= '</tr>';

	$body .= '<tr style="background-color: #f8f9fa; border-bottom: 1px solid #dee2e6;">';
	$body .= '<td style="font-weight: bold; padding: 8px 12px; border: 1px solid #dee2e6;">Utilization</td>';
	$body .= '<td style="padding: 8px 12px; border: 1px solid #dee2e6;">';
	$body .= '<strong style="color: ' . $bar_color . ';">' . $pct . '%</strong>';
	$body .= '</td>';
	$body .= '</tr>';

	$body .= '<tr style="border-bottom: 1px solid #dee2e6;">';
	$body .= '<td style="font-weight: bold; padding: 8px 12px; border: 1px solid #dee2e6;">Used / Total Addresses</td>';
	$body .= '<td style="padding: 8px 12px; border: 1px solid #dee2e6;">' . $used . ' / ' . $total . ' (' . $free . ' free)</td>';
	$body .= '</tr>';

	$body .= '<tr style="background-color: #f8f9fa; border-bottom: 1px solid #dee2e6;">';
	$body .= '<td style="font-weight: bold; padding: 8px 12px; border: 1px solid #dee2e6;">Threshold Setting</td>';
	$body .= '<td style="padding: 8px 12px; border: 1px solid #dee2e6;">' . $threshold . '%</td>';
	$body .= '</tr>';

	$body .= '<tr style="border-bottom: 1px solid #dee2e6;">';
	$body .= '<td style="font-weight: bold; padding: 8px 12px; border: 1px solid #dee2e6;">Gateway</td>';
	$body .= '<td style="padding: 8px 12px; border: 1px solid #dee2e6;">' . ($gateway !== '' ? $gateway : '<em>Not set</em>') . '</td>';
	$body .= '</tr>';

	$body .= '</table>';

	$body .= '<p style="font-size: 12px; color: #888; margin-top: 20px;">This alert was generated by the Cereus IPAM plugin for Cacti.</p>';
	$body .= '</body></html>';

	/* Build plain-text version */
	$body_text  = "Subnet Utilization Alert\n";
	$body_text .= "========================\n\n";
	$body_text .= "Subnet:              " . $subnet['subnet'] . '/' . $subnet['mask'] . "\n";
	$body_text .= "Description:         " . ($subnet['description'] ?? '') . "\n";
	$body_text .= "Utilization:         " . $pct . "%\n";
	$body_text .= "Used / Total:        " . $used . ' / ' . $total . ' (' . $free . " free)\n";
	$body_text .= "Threshold Setting:   " . $threshold . "%\n";
	$body_text .= "Gateway:             " . ($subnet['gateway'] ?? 'Not set') . "\n\n";
	$body_text .= "-- \nGenerated by Cereus IPAM plugin for Cacti.\n";

	/* Send via Cacti mailer */
	$error = mailer(
		'',             /* from - uses Cacti default */
		$emails,        /* to */
		'',             /* cc */
		'',             /* bcc */
		'',             /* replyto */
		$subject,       /* subject */
		$body,          /* body (HTML) */
		$body_text,     /* body_text (plain) */
		array(),        /* attachments */
		array(),        /* headers */
		true            /* html */
	);

	if ($error == '') {
		return true;
	}

	cacti_log('CEREUS IPAM WARNING: Mailer error for threshold alert: ' . $error, false, 'PLUGIN');

	return false;
}

/**
 * Get threshold status for a given subnet, used by the UI
 * to display alert state on subnet views.
 *
 * @param int $subnet_id  The subnet ID
 * @return array           Keys: exceeded (bool), pct (int), threshold (int), last_alert (int|null)
 */
function cereus_ipam_threshold_status($subnet_id) {
	$subnet_id = (int) $subnet_id;

	/* Get the threshold setting for this subnet */
	$threshold = db_fetch_row_prepared(
		"SELECT threshold_pct FROM plugin_cereus_ipam_subnets WHERE id = ?",
		array($subnet_id)
	);

	if (!cacti_sizeof($threshold)) {
		return array(
			'exceeded'   => false,
			'pct'        => 0,
			'threshold'  => 0,
			'last_alert' => null,
		);
	}

	$threshold_pct = (int) $threshold['threshold_pct'];

	/* Get current utilization */
	$utilization = cereus_ipam_subnet_utilization($subnet_id);
	$current_pct = (int) $utilization['pct'];

	/* Get last alert timestamp */
	$last_alert_key = 'cereus_ipam_threshold_last_' . $subnet_id;
	$last_alert_raw = read_config_option($last_alert_key);
	$last_alert     = !empty($last_alert_raw) ? (int) $last_alert_raw : null;

	/* Determine if threshold is exceeded */
	$exceeded = ($threshold_pct > 0 && $current_pct >= $threshold_pct);

	return array(
		'exceeded'   => $exceeded,
		'pct'        => $current_pct,
		'threshold'  => $threshold_pct,
		'last_alert' => $last_alert,
	);
}
