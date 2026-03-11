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
 | Cereus IPAM - Maintenance Window Management (Enterprise)                |
 +-------------------------------------------------------------------------+
*/

/**
 * Check if there is currently an active maintenance window.
 * If $subnet_id is provided, check if that specific subnet is covered
 * (its ID is in subnet_ids, or subnet_ids contains 'all').
 *
 * @param int|null $subnet_id  Optional subnet ID to check
 * @return bool                True if in maintenance
 */
function cereus_ipam_is_in_maintenance($subnet_id = null) {
	$windows = db_fetch_assoc("SELECT * FROM plugin_cereus_ipam_maintenance
		WHERE start_time <= NOW() AND end_time >= NOW()");

	if (!cacti_sizeof($windows)) {
		return false;
	}

	if ($subnet_id === null) {
		return true;
	}

	$subnet_id = (int) $subnet_id;

	foreach ($windows as $window) {
		$ids = trim($window['subnet_ids']);

		if (strtolower($ids) === 'all') {
			return true;
		}

		$id_list = array_map('trim', explode(',', $ids));

		if (in_array((string) $subnet_id, $id_list, true)) {
			return true;
		}
	}

	return false;
}

/**
 * Return array of currently active maintenance windows.
 *
 * @return array  Array of maintenance window rows
 */
function cereus_ipam_get_active_maintenance() {
	return db_fetch_assoc("SELECT * FROM plugin_cereus_ipam_maintenance
		WHERE start_time <= NOW() AND end_time >= NOW()
		ORDER BY start_time ASC");
}

/**
 * Check if scanning should be suppressed for a given subnet.
 * Returns true if there is an active maintenance window that
 * includes this subnet AND has suppress_scans=1.
 *
 * @param int $subnet_id  The subnet ID to check
 * @return bool           True if scanning should be suppressed
 */
function cereus_ipam_should_suppress_scan($subnet_id) {
	$subnet_id = (int) $subnet_id;

	$windows = db_fetch_assoc("SELECT * FROM plugin_cereus_ipam_maintenance
		WHERE start_time <= NOW() AND end_time >= NOW()
		AND suppress_scans = 1");

	if (!cacti_sizeof($windows)) {
		return false;
	}

	foreach ($windows as $window) {
		$ids = trim($window['subnet_ids']);

		if (strtolower($ids) === 'all') {
			return true;
		}

		$id_list = array_map('trim', explode(',', $ids));

		if (in_array((string) $subnet_id, $id_list, true)) {
			return true;
		}
	}

	return false;
}

/**
 * Check if alerts should be suppressed for a given subnet.
 * Returns true if there is an active maintenance window that
 * includes this subnet AND has suppress_alerts=1.
 *
 * @param int $subnet_id  The subnet ID to check
 * @return bool           True if alerts should be suppressed
 */
function cereus_ipam_should_suppress_alert($subnet_id) {
	$subnet_id = (int) $subnet_id;

	$windows = db_fetch_assoc("SELECT * FROM plugin_cereus_ipam_maintenance
		WHERE start_time <= NOW() AND end_time >= NOW()
		AND suppress_alerts = 1");

	if (!cacti_sizeof($windows)) {
		return false;
	}

	foreach ($windows as $window) {
		$ids = trim($window['subnet_ids']);

		if (strtolower($ids) === 'all') {
			return true;
		}

		$id_list = array_map('trim', explode(',', $ids));

		if (in_array((string) $subnet_id, $id_list, true)) {
			return true;
		}
	}

	return false;
}
