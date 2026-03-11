<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2024-2026 Urban-Software.de / Thomas Urban               |
 +-------------------------------------------------------------------------+
 | Cereus IPAM - Audit Trail / Changelog                                   |
 +-------------------------------------------------------------------------+
*/

/**
 * Record a changelog entry.
 *
 * @param string $action      One of: create, update, delete, import, scan, truncate
 * @param string $object_type One of: section, subnet, address, vlan, vrf, custom_field, setting
 * @param int    $object_id   The ID of the affected object
 * @param mixed  $old_value   Previous state (array or null)
 * @param mixed  $new_value   New state (array or null)
 */
function cereus_ipam_changelog_record($action, $object_type, $object_id, $old_value = null, $new_value = null) {
	$user_id = $_SESSION['sess_user_id'] ?? 0;
	$ip_addr = $_SERVER['REMOTE_ADDR'] ?? '';

	db_execute_prepared("INSERT INTO plugin_cereus_ipam_changelog
		(user_id, action, object_type, object_id, old_value, new_value, ip_address)
		VALUES (?, ?, ?, ?, ?, ?, ?)",
		array(
			$user_id,
			$action,
			$object_type,
			$object_id,
			$old_value !== null ? json_encode($old_value, JSON_UNESCAPED_SLASHES) : null,
			$new_value !== null ? json_encode($new_value, JSON_UNESCAPED_SLASHES) : null,
			$ip_addr,
		)
	);

	/* Dispatch webhook if enabled */
	if (function_exists('cereus_ipam_webhook_dispatch')) {
		cereus_ipam_webhook_dispatch($action, $object_type, $object_id, array(
			'old_value' => $old_value,
			'new_value' => $new_value,
		));
	}
}

/**
 * Purge old changelog entries based on retention policy.
 *
 * @param int $days Number of days to retain. 0 = unlimited.
 */
function cereus_ipam_changelog_purge($days) {
	if ($days <= 0) {
		return;
	}

	db_execute_prepared("DELETE FROM plugin_cereus_ipam_changelog
		WHERE created < DATE_SUB(NOW(), INTERVAL ? DAY)",
		array($days)
	);
}

/**
 * Get the username for a given user_id.
 */
function cereus_ipam_get_username($user_id) {
	if ($user_id <= 0) {
		return __('System', 'cereus_ipam');
	}
	$name = db_fetch_cell_prepared("SELECT username FROM user_auth WHERE id = ?", array($user_id));
	return !empty($name) ? $name : __('Unknown', 'cereus_ipam');
}
