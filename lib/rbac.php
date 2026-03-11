<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2024-2026 Urban-Software.de / Thomas Urban               |
 +-------------------------------------------------------------------------+
 | Cereus IPAM - Per-Section RBAC                                          |
 +-------------------------------------------------------------------------+
*/

/**
 * Permission level ranking used for comparison.
 *
 * @return array  Associative array of level => numeric rank.
 */
function cereus_ipam_permission_ranks() {
	return array(
		'view'  => 1,
		'edit'  => 2,
		'admin' => 3,
	);
}

/**
 * Get all Cacti auth group IDs for a user.
 *
 * Only returns groups that are enabled (enabled = 'on').
 *
 * @param  int   $user_id
 * @return array Array of group IDs.
 */
function cereus_ipam_get_user_groups($user_id) {
	return array_column(
		db_fetch_assoc_prepared(
			"SELECT gm.group_id
			 FROM user_auth_group_members gm
			 INNER JOIN user_auth_group g ON g.id = gm.group_id
			 WHERE gm.user_id = ? AND g.enabled = 'on'",
			array($user_id)
		),
		'group_id'
	);
}

/**
 * Get the highest permission level from an array of levels.
 *
 * @param  array        $levels  Array of permission level strings.
 * @return string|false Highest level or false if none.
 */
function cereus_ipam_highest_permission($levels) {
	$ranks    = cereus_ipam_permission_ranks();
	$max_rank = 0;
	$max_level = false;

	foreach ($levels as $level) {
		if (isset($ranks[$level]) && $ranks[$level] > $max_rank) {
			$max_rank  = $ranks[$level];
			$max_level = $level;
		}
	}

	return $max_level;
}

/**
 * Get the current user's permission level for a section.
 *
 * Returns a permission level string ('view', 'edit', 'admin') or false if the
 * user has no permission at all.
 *
 * When RBAC is not licensed (community tier), returns 'admin' for everyone.
 * When the section has empty/null permissions, returns 'admin' (unrestricted).
 * Cacti admin (user_id 1) always gets 'admin'.
 *
 * @param  int       $section_id  The section ID to check.
 * @param  int|null  $user_id     The Cacti user ID, or null for current session user.
 * @return string|false  Permission level or false if denied.
 */
function cereus_ipam_section_permission($section_id, $user_id = null) {
	/* Resolve user ID from session if not provided */
	if ($user_id === null) {
		$user_id = isset($_SESSION['sess_user_id']) ? (int) $_SESSION['sess_user_id'] : 0;
	} else {
		$user_id = (int) $user_id;
	}

	/* If RBAC is not licensed, grant full access to everyone */
	if (!cereus_ipam_license_has_rbac()) {
		return 'admin';
	}

	/* Cacti admin always has full access */
	if ($user_id === 1) {
		return 'admin';
	}

	/* Fetch the section's permissions JSON */
	$permissions_json = db_fetch_cell_prepared(
		"SELECT permissions FROM plugin_cereus_ipam_sections WHERE id = ?",
		array($section_id)
	);

	/* Empty, null, or invalid JSON means unrestricted access */
	if ($permissions_json === null || $permissions_json === '' || $permissions_json === false) {
		return 'admin';
	}

	$permissions = json_decode($permissions_json, true);

	if (!is_array($permissions) || empty($permissions)) {
		return 'admin';
	}

	$uid_str = (string) $user_id;
	$ranks   = cereus_ipam_permission_ranks();

	/* Determine format: new (has 'users' key) or old (flat) */
	$is_new_format = isset($permissions['users']);

	if (!$is_new_format) {
		/* Old flat format: {"3": "view", "5": "edit"} */
		if (isset($permissions[$uid_str]) && isset($ranks[$permissions[$uid_str]])) {
			return $permissions[$uid_str];
		}

		return false;
	}

	/* New format: {"users": {...}, "groups": {...}} */
	$user_perms  = isset($permissions['users']) && is_array($permissions['users']) ? $permissions['users'] : array();
	$group_perms = isset($permissions['groups']) && is_array($permissions['groups']) ? $permissions['groups'] : array();

	/* Direct user permission */
	$user_level = false;

	if (isset($user_perms[$uid_str]) && isset($ranks[$user_perms[$uid_str]])) {
		$user_level = $user_perms[$uid_str];
	}

	/* Group permission (Enterprise only — requires LDAP license) */
	$group_level = false;

	if (cereus_ipam_license_has_ldap() && cacti_sizeof($group_perms)) {
		$user_groups = cereus_ipam_get_user_groups($user_id);

		if (cacti_sizeof($user_groups)) {
			$matched_levels = array();

			foreach ($user_groups as $gid) {
				$gid_str = (string) $gid;

				if (isset($group_perms[$gid_str]) && isset($ranks[$group_perms[$gid_str]])) {
					$matched_levels[] = $group_perms[$gid_str];
				}
			}

			if (cacti_sizeof($matched_levels)) {
				$group_level = cereus_ipam_highest_permission($matched_levels);
			}
		}
	}

	/* Return the higher of user and group permission */
	if ($user_level !== false && $group_level !== false) {
		return cereus_ipam_highest_permission(array($user_level, $group_level));
	} elseif ($user_level !== false) {
		return $user_level;
	} elseif ($group_level !== false) {
		return $group_level;
	}

	/* Neither user nor group permission found — no access */
	return false;
}

/**
 * Check if a user meets the minimum permission level for a section.
 *
 * @param  int       $section_id     The section ID to check.
 * @param  string    $required_level Required level: 'view', 'edit', or 'admin'.
 * @param  int|null  $user_id        The Cacti user ID, or null for current session user.
 * @return bool      True if user meets or exceeds the required level.
 */
function cereus_ipam_check_section_permission($section_id, $required_level, $user_id = null) {
	$current_level = cereus_ipam_section_permission($section_id, $user_id);

	if ($current_level === false) {
		return false;
	}

	$ranks = cereus_ipam_permission_ranks();

	$current_rank  = isset($ranks[$current_level]) ? $ranks[$current_level] : 0;
	$required_rank = isset($ranks[$required_level]) ? $ranks[$required_level] : 0;

	return $current_rank >= $required_rank;
}

/**
 * Filter an array of section rows by the current user's permission level.
 *
 * @param  array   $sections   Array of section rows, each with an 'id' key.
 * @param  string  $min_level  Minimum permission level: 'view', 'edit', or 'admin'.
 * @return array   Filtered array of sections the user has access to.
 */
function cereus_ipam_filter_sections_by_permission($sections, $min_level = 'view') {
	if (!cacti_sizeof($sections)) {
		return array();
	}

	/* If RBAC is not licensed, return all sections unfiltered */
	if (!cereus_ipam_license_has_rbac()) {
		return $sections;
	}

	$result = array();

	foreach ($sections as $section) {
		if (cereus_ipam_check_section_permission($section['id'], $min_level)) {
			$result[] = $section;
		}
	}

	return $result;
}

/**
 * Filter an array of subnet rows by the current user's permission on the parent section.
 *
 * @param  array   $subnets    Array of subnet rows, each with a 'section_id' key.
 * @param  string  $min_level  Minimum permission level: 'view', 'edit', or 'admin'.
 * @return array   Filtered array of subnets the user has access to.
 */
function cereus_ipam_filter_subnets_by_permission($subnets, $min_level = 'view') {
	if (!cacti_sizeof($subnets)) {
		return array();
	}

	/* If RBAC is not licensed, return all subnets unfiltered */
	if (!cereus_ipam_license_has_rbac()) {
		return $subnets;
	}

	$result = array();

	/* Cache permission checks per section_id to avoid repeated DB queries */
	$cache = array();

	foreach ($subnets as $subnet) {
		$sid = $subnet['section_id'];

		if (!isset($cache[$sid])) {
			$cache[$sid] = cereus_ipam_check_section_permission($sid, $min_level);
		}

		if ($cache[$sid]) {
			$result[] = $subnet;
		}
	}

	return $result;
}

/**
 * Render the permissions editor HTML for the section edit form.
 *
 * Outputs an HTML table inside an html_start_box/html_end_box with a dropdown
 * per user allowing None/View/Edit/Admin selection. Cacti admin (user_id 1) is
 * shown with a fixed "Admin (always)" label.
 *
 * @param  int  $section_id  The section ID (0 for new sections).
 */
function cereus_ipam_render_permissions_editor($section_id) {
	/* Fetch all Cacti users */
	$users = db_fetch_assoc("SELECT id, username, full_name FROM user_auth ORDER BY username");

	/* Fetch current permissions for this section */
	$permissions_raw = array();

	if ($section_id > 0) {
		$permissions_json = db_fetch_cell_prepared(
			"SELECT permissions FROM plugin_cereus_ipam_sections WHERE id = ?",
			array($section_id)
		);

		if ($permissions_json !== null && $permissions_json !== '' && $permissions_json !== false) {
			$decoded = json_decode($permissions_json, true);
			if (is_array($decoded)) {
				$permissions_raw = $decoded;
			}
		}
	}

	/* Determine format and extract user/group permissions */
	$is_new_format = isset($permissions_raw['users']);

	if ($is_new_format) {
		$user_permissions  = isset($permissions_raw['users']) && is_array($permissions_raw['users']) ? $permissions_raw['users'] : array();
		$group_permissions = isset($permissions_raw['groups']) && is_array($permissions_raw['groups']) ? $permissions_raw['groups'] : array();
	} else {
		/* Old flat format — all entries are user permissions */
		$user_permissions  = $permissions_raw;
		$group_permissions = array();
	}

	$levels = array(
		''      => __('None', 'cereus_ipam'),
		'view'  => __('View', 'cereus_ipam'),
		'edit'  => __('Edit', 'cereus_ipam'),
		'admin' => __('Admin', 'cereus_ipam'),
	);

	/* ---- User Permissions Table ---- */
	html_start_box(__('Section Permissions', 'cereus_ipam'), '100%', '', '3', 'center', '');

	print '<tr class="tableHeader">';
	print '<th class="tableSubHeaderColumn">' . __('User', 'cereus_ipam') . '</th>';
	print '<th class="tableSubHeaderColumn">' . __('Permission Level', 'cereus_ipam') . '</th>';
	print '</tr>';

	if (cacti_sizeof($users)) {
		$i = 0;

		foreach ($users as $user) {
			$uid_str = (string) $user['id'];
			$display_name = html_escape($user['username']);

			if (!empty($user['full_name'])) {
				$display_name .= ' (' . html_escape($user['full_name']) . ')';
			}

			print '<tr class="' . (($i % 2 == 0) ? 'odd' : 'even') . '">';
			print '<td>' . $display_name . '</td>';
			print '<td>';

			if ((int) $user['id'] === 1) {
				/* Admin always has full access */
				print '<em>' . __('Admin (always)', 'cereus_ipam') . '</em>';
			} else {
				$current_level = isset($user_permissions[$uid_str]) ? $user_permissions[$uid_str] : '';

				print '<select name="perm_user_' . (int) $user['id'] . '">';

				foreach ($levels as $value => $label) {
					$selected = ($current_level === $value) ? ' selected' : '';
					print '<option value="' . html_escape($value) . '"' . $selected . '>' . $label . '</option>';
				}

				print '</select>';
			}

			print '</td>';
			print '</tr>';

			$i++;
		}
	} else {
		print '<tr><td colspan="2"><em>' . __('No users found.', 'cereus_ipam') . '</em></td></tr>';
	}

	html_end_box();

	/* ---- Group Permissions Table (Enterprise only) ---- */
	if (cereus_ipam_license_has_ldap()) {
		$groups = db_fetch_assoc("SELECT id, name, description FROM user_auth_group WHERE enabled = 'on' ORDER BY name");

		html_start_box(__('Group Permissions (LDAP/AD)', 'cereus_ipam'), '100%', '', '3', 'center', '');

		print '<tr class="tableHeader">';
		print '<th class="tableSubHeaderColumn">' . __('Group', 'cereus_ipam') . '</th>';
		print '<th class="tableSubHeaderColumn">' . __('Description', 'cereus_ipam') . '</th>';
		print '<th class="tableSubHeaderColumn">' . __('Permission Level', 'cereus_ipam') . '</th>';
		print '</tr>';

		if (cacti_sizeof($groups)) {
			$i = 0;

			foreach ($groups as $group) {
				$gid_str = (string) $group['id'];
				$current_level = isset($group_permissions[$gid_str]) ? $group_permissions[$gid_str] : '';

				print '<tr class="' . (($i % 2 == 0) ? 'odd' : 'even') . '">';
				print '<td>' . html_escape($group['name']) . '</td>';
				print '<td>' . html_escape($group['description'] ?? '') . '</td>';
				print '<td>';

				print '<select name="perm_group_' . (int) $group['id'] . '">';

				foreach ($levels as $value => $label) {
					$selected = ($current_level === $value) ? ' selected' : '';
					print '<option value="' . html_escape($value) . '"' . $selected . '>' . $label . '</option>';
				}

				print '</select>';

				print '</td>';
				print '</tr>';

				$i++;
			}
		} else {
			print '<tr><td colspan="3"><em>' . __('No enabled auth groups found. Configure groups in Cacti user management.', 'cereus_ipam') . '</em></td></tr>';
		}

		html_end_box();
	}
}

/**
 * Collect and save section permissions from POST data.
 *
 * Iterates through POST variables matching perm_user_(\d+), builds a
 * permissions array, and saves it as JSON to the section's permissions column.
 *
 * @param  int     $section_id  The section ID to update.
 * @return string  The JSON-encoded permissions string that was saved.
 */
function cereus_ipam_save_section_permissions($section_id) {
	$ranks = cereus_ipam_permission_ranks();

	/* Collect user permissions from perm_user_N POST vars */
	$user_permissions = array();

	foreach ($_POST as $key => $value) {
		if (preg_match('/^perm_user_(\d+)$/', $key, $matches)) {
			$uid   = $matches[1];
			$level = $value;

			/* Skip user ID 1 (always admin) */
			if ((int) $uid === 1) {
				continue;
			}

			/* Skip empty/none values */
			if ($level === '' || $level === null) {
				continue;
			}

			/* Validate the level is a known value */
			if (isset($ranks[$level])) {
				$user_permissions[$uid] = $level;
			}
		}
	}

	/* Collect group permissions from perm_group_N POST vars */
	$group_permissions = array();

	foreach ($_POST as $key => $value) {
		if (preg_match('/^perm_group_(\d+)$/', $key, $matches)) {
			$gid   = $matches[1];
			$level = $value;

			/* Skip empty/none values */
			if ($level === '' || $level === null) {
				continue;
			}

			/* Validate the level is a known value */
			if (isset($ranks[$level])) {
				$group_permissions[$gid] = $level;
			}
		}
	}

	/* Build final JSON structure */
	if (cereus_ipam_license_has_ldap()) {
		/* Enterprise: always use new nested format */
		$permissions = array(
			'users'  => $user_permissions,
			'groups' => $group_permissions,
		);
	} else {
		/* Non-Enterprise: save in old flat format for backwards compatibility */
		$permissions = $user_permissions;
	}

	$json = json_encode($permissions);

	db_execute_prepared(
		"UPDATE plugin_cereus_ipam_sections SET permissions = ? WHERE id = ?",
		array($json, $section_id)
	);

	return $json;
}
