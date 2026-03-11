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
 | Cereus IPAM - Capacity Forecasting (Enterprise)                         |
 +-------------------------------------------------------------------------+
*/

/**
 * Record current utilization for all subnets into the history table.
 * Called from poller_bottom; runs at most once per hour.
 */
function cereus_ipam_record_utilization() {
	$last_run = read_config_option('cereus_ipam_util_last_record');

	if ($last_run !== false && $last_run !== '' && (time() - intval($last_run)) < 3600) {
		return;
	}

	$subnets = db_fetch_assoc("SELECT id FROM plugin_cereus_ipam_subnets");

	if (!cacti_sizeof($subnets)) {
		return;
	}

	foreach ($subnets as $row) {
		$util = cereus_ipam_subnet_utilization($row['id']);

		db_execute_prepared(
			"INSERT INTO plugin_cereus_ipam_utilization_history
				(subnet_id, used, total, pct)
			VALUES (?, ?, ?, ?)",
			array(
				$row['id'],
				$util['used'],
				$util['total'],
				$util['pct']
			)
		);
	}

	set_config_option('cereus_ipam_util_last_record', time());
}

/**
 * Calculate predicted exhaustion date for a subnet using linear regression
 * on the last 30 days of hourly utilization data.
 *
 * @param  int        $subnet_id  The subnet ID
 * @return array|null             Forecast data or null if insufficient data / no exhaustion predicted
 */
function cereus_ipam_forecast_exhaustion($subnet_id) {
	$rows = db_fetch_assoc_prepared(
		"SELECT pct, UNIX_TIMESTAMP(recorded_at) AS ts
		FROM plugin_cereus_ipam_utilization_history
		WHERE subnet_id = ?
			AND recorded_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
		ORDER BY recorded_at",
		array($subnet_id)
	);

	if (!cacti_sizeof($rows) || cacti_sizeof($rows) < 24) {
		return null;
	}

	$n      = cacti_sizeof($rows);
	$sum_x  = 0;
	$sum_y  = 0;
	$sum_xy = 0;
	$sum_xx = 0;

	foreach ($rows as $row) {
		$x = (float) $row['ts'];
		$y = (float) $row['pct'];

		$sum_x  += $x;
		$sum_y  += $y;
		$sum_xy += $x * $y;
		$sum_xx += $x * $x;
	}

	$denominator = ($n * $sum_xx) - ($sum_x * $sum_x);

	if ($denominator == 0) {
		return null;
	}

	$m = (($n * $sum_xy) - ($sum_x * $sum_y)) / $denominator;
	$b = ($sum_y - ($m * $sum_x)) / $n;

	/* Determine trend */
	if ($m <= 0) {
		return null;
	}

	$trend = 'increasing';

	/* Calculate time when pct reaches 100 */
	$t_exhaust = (100 - $b) / $m;

	$now = time();

	/* If exhaustion date is in the past, return null */
	if ($t_exhaust <= $now) {
		return null;
	}

	/* If more than 5 years out, return null */
	$five_years = $now + (5 * 365 * 86400);
	if ($t_exhaust > $five_years) {
		return null;
	}

	$exhaustion_date = date('Y-m-d', (int) $t_exhaust);
	$days_remaining  = (int) ceil(($t_exhaust - $now) / 86400);
	$daily_growth    = round($m * 86400, 4); /* slope is pct per second, convert to pct per day */

	return array(
		'exhaustion_date' => $exhaustion_date,
		'days_remaining'  => $days_remaining,
		'trend'           => $trend,
		'daily_growth'    => $daily_growth,
	);
}

/**
 * Fetch historical utilization data for a subnet, grouped by day.
 *
 * @param  int   $subnet_id  The subnet ID
 * @param  int   $days       Number of days of history (default 30)
 * @return array              Array of rows with day, avg_pct, max_pct, min_pct
 */
function cereus_ipam_get_utilization_history($subnet_id, $days = 30) {
	$rows = db_fetch_assoc_prepared(
		"SELECT DATE(recorded_at) AS day,
			ROUND(AVG(pct)) AS avg_pct,
			MAX(pct) AS max_pct,
			MIN(pct) AS min_pct
		FROM plugin_cereus_ipam_utilization_history
		WHERE subnet_id = ?
			AND recorded_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
		GROUP BY DATE(recorded_at)
		ORDER BY day",
		array($subnet_id, $days)
	);

	return cacti_sizeof($rows) ? $rows : array();
}

/**
 * Get forecast summary for ALL subnets, sorted by urgency (days_remaining ascending).
 *
 * @return array  Array of forecast entries with subnet details
 */
function cereus_ipam_forecast_summary() {
	$subnets = db_fetch_assoc(
		"SELECT id, CONCAT(subnet, '/', mask) AS cidr, description
		FROM plugin_cereus_ipam_subnets
		ORDER BY subnet"
	);

	if (!cacti_sizeof($subnets)) {
		return array();
	}

	$results = array();

	foreach ($subnets as $s) {
		$forecast = cereus_ipam_forecast_exhaustion($s['id']);

		if ($forecast === null) {
			continue;
		}

		$util = cereus_ipam_subnet_utilization($s['id']);

		$results[] = array(
			'subnet_id'       => $s['id'],
			'subnet'          => $s['cidr'],
			'description'     => $s['description'],
			'current_pct'     => $util['pct'],
			'exhaustion_date' => $forecast['exhaustion_date'],
			'days_remaining'  => $forecast['days_remaining'],
			'daily_growth'    => $forecast['daily_growth'],
		);
	}

	/* Sort by days_remaining ascending (most urgent first) */
	usort($results, function ($a, $b) {
		return $a['days_remaining'] - $b['days_remaining'];
	});

	return $results;
}
