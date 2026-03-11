<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2024-2026 Urban-Software.de / Thomas Urban               |
 +-------------------------------------------------------------------------+
 | Cereus IPAM - Core Functions                                            |
 +-------------------------------------------------------------------------+
*/

/**
 * Get all sections as a flat list, with depth indicator for hierarchy display.
 */
function cereus_ipam_get_sections_tree($parent_id = 0, $depth = 0) {
	$sections = db_fetch_assoc_prepared("SELECT * FROM plugin_cereus_ipam_sections
		WHERE parent_id = ? ORDER BY display_order, name",
		array($parent_id));

	$result = array();
	if (cacti_sizeof($sections)) {
		foreach ($sections as $s) {
			$s['depth'] = $depth;
			$result[] = $s;
			$children = cereus_ipam_get_sections_tree($s['id'], $depth + 1);
			$result = array_merge($result, $children);
		}
	}
	return $result;
}

/**
 * Get sections as a dropdown array with indentation.
 */
function cereus_ipam_get_sections_dropdown() {
	$tree = cereus_ipam_get_sections_tree();
	$dropdown = array(0 => __('None (Top Level)', 'cereus_ipam'));
	foreach ($tree as $s) {
		$prefix = str_repeat('-- ', $s['depth']);
		$dropdown[$s['id']] = $prefix . $s['name'];
	}
	return $dropdown;
}

/**
 * Get subnets for a given section.
 */
function cereus_ipam_get_section_subnets($section_id) {
	return db_fetch_assoc_prepared("SELECT * FROM plugin_cereus_ipam_subnets
		WHERE section_id = ? ORDER BY subnet, mask",
		array($section_id));
}

/**
 * Auto-link Cacti devices to IPAM addresses.
 * Matches host.hostname to address IPs.
 * Creates address records for devices in managed subnets if they don't exist.
 */
function cereus_ipam_device_sync() {
	/* Get all Cacti hosts */
	$hosts = db_fetch_assoc("SELECT id, description, hostname, status FROM host");

	/* Pre-load all managed subnets for matching */
	$subnets = db_fetch_assoc("SELECT id, subnet, mask FROM plugin_cereus_ipam_subnets");

	if (!cacti_sizeof($hosts) || !cacti_sizeof($subnets)) {
		return;
	}

	foreach ($hosts as $host) {
		$ip = $host['hostname'];

		/* Only process if hostname is an IP address */
		if (!cereus_ipam_validate_ip($ip)) {
			/* Try to resolve hostname to IP and match that way */
			$resolved = @gethostbyname($ip);
			if ($resolved === $ip || !cereus_ipam_validate_ip($resolved)) {
				continue;
			}
			$ip = $resolved;
		}

		/* Find matching address record */
		$addr = db_fetch_row_prepared("SELECT id, cacti_host_id, state
			FROM plugin_cereus_ipam_addresses WHERE ip = ?",
			array($ip));

		$new_state = ($host['status'] == 3) ? 'active' : 'offline';

		if (cacti_sizeof($addr)) {
			/* Existing record — update link and state */
			$updates = array();
			$params  = array();

			if ((int) $addr['cacti_host_id'] !== (int) $host['id']) {
				$updates[] = 'cacti_host_id = ?';
				$params[]  = $host['id'];
			}

			if ($addr['state'] !== $new_state && $addr['state'] !== 'reserved' && $addr['state'] !== 'dhcp') {
				$updates[] = 'state = ?';
				$params[]  = $new_state;
			}

			if (cacti_sizeof($updates)) {
				$updates[] = 'last_seen = NOW()';
				$params[]  = $addr['id'];
				db_execute_prepared("UPDATE plugin_cereus_ipam_addresses SET "
					. implode(', ', $updates) . " WHERE id = ?",
					$params);
			}
		} else {
			/* No address record — find which managed subnet this IP belongs to and auto-create */
			$matched_subnet_id = null;

			foreach ($subnets as $s) {
				if (cereus_ipam_ip_in_subnet($ip, $s['subnet'], $s['mask'])) {
					$matched_subnet_id = $s['id'];
					break;
				}
			}

			if ($matched_subnet_id !== null) {
				db_execute_prepared("INSERT IGNORE INTO plugin_cereus_ipam_addresses
					(subnet_id, ip, hostname, description, state, cacti_host_id, last_seen, created_by)
					VALUES (?, ?, ?, ?, ?, ?, NOW(), 0)",
					array(
						$matched_subnet_id,
						$ip,
						$host['hostname'],
						$host['description'],
						$new_state,
						$host['id'],
					));
			}
		}
	}
}

/**
 * Get a utilization bar HTML for display.
 */
function cereus_ipam_utilization_bar($pct) {
	$pct = max(0, min(100, $pct));

	if ($pct >= 90) {
		$color = '#F44336';
	} elseif ($pct >= 75) {
		$color = '#FF9800';
	} else {
		$color = '#4CAF50';
	}

	return '<div style="width:100px;height:16px;background:#e0e0e0;border-radius:3px;display:inline-block;vertical-align:middle;" title="' . $pct . '%">'
		. '<div style="width:' . $pct . '%;height:100%;background:' . $color . ';border-radius:3px;"></div>'
		. '</div> <span style="font-size:11px;">' . $pct . '%</span>';
}

/**
 * Get VLANs as a dropdown array.
 */
function cereus_ipam_get_vlans_dropdown() {
	$vlans = db_fetch_assoc("SELECT id, vlan_number, name FROM plugin_cereus_ipam_vlans ORDER BY vlan_number");
	$dropdown = array('' => __('None', 'cereus_ipam'));
	if (cacti_sizeof($vlans)) {
		foreach ($vlans as $v) {
			$dropdown[$v['id']] = $v['vlan_number'] . ' - ' . $v['name'];
		}
	}
	return $dropdown;
}

/**
 * Get VRFs as a dropdown array.
 */
function cereus_ipam_get_vrfs_dropdown() {
	$vrfs = db_fetch_assoc("SELECT id, name, rd FROM plugin_cereus_ipam_vrfs ORDER BY name");
	$dropdown = array('' => __('None', 'cereus_ipam'));
	if (cacti_sizeof($vrfs)) {
		foreach ($vrfs as $v) {
			$label = $v['name'];
			if (!empty($v['rd'])) {
				$label .= ' (RD: ' . $v['rd'] . ')';
			}
			$dropdown[$v['id']] = $label;
		}
	}
	return $dropdown;
}

/**
 * Find the best parent subnet for a given subnet address/mask.
 * The parent is the smallest existing subnet that fully contains this one.
 * Returns parent_id or 0 if none found.
 */
function cereus_ipam_find_parent_subnet($subnet_addr, $mask, $section_id, $exclude_id = 0) {
	/* A parent must have a smaller mask (larger network) and contain our network */
	$candidates = db_fetch_assoc_prepared(
		"SELECT id, subnet, mask FROM plugin_cereus_ipam_subnets
		WHERE section_id = ? AND mask < ? AND id != ?
		ORDER BY mask DESC",
		array($section_id, $mask, $exclude_id)
	);

	if (cacti_sizeof($candidates)) {
		foreach ($candidates as $c) {
			if (cereus_ipam_ip_in_subnet($subnet_addr, $c['subnet'], $c['mask'])) {
				return (int) $c['id'];
			}
		}
	}

	return 0;
}

/**
 * After creating/updating a subnet, check if any existing subnets
 * in the same section should become children of this one.
 */
function cereus_ipam_reparent_children($parent_id, $parent_subnet, $parent_mask, $section_id) {
	/* Find subnets with a larger mask that fit inside this one */
	$candidates = db_fetch_assoc_prepared(
		"SELECT id, subnet, mask, parent_id FROM plugin_cereus_ipam_subnets
		WHERE section_id = ? AND mask > ? AND id != ?",
		array($section_id, $parent_mask, $parent_id)
	);

	if (!cacti_sizeof($candidates)) {
		return;
	}

	foreach ($candidates as $c) {
		if (cereus_ipam_ip_in_subnet($c['subnet'], $parent_subnet, $parent_mask)) {
			/* Only reparent if currently at top level (parent_id=0) or if the
			   current parent is less specific than us */
			if ($c['parent_id'] == 0) {
				db_execute_prepared("UPDATE plugin_cereus_ipam_subnets SET parent_id = ? WHERE id = ?",
					array($parent_id, $c['id']));
			} else {
				/* Check if we are more specific than the current parent */
				$current_parent = db_fetch_row_prepared(
					"SELECT mask FROM plugin_cereus_ipam_subnets WHERE id = ?",
					array($c['parent_id'])
				);
				if (cacti_sizeof($current_parent) && $parent_mask > $current_parent['mask']) {
					db_execute_prepared("UPDATE plugin_cereus_ipam_subnets SET parent_id = ? WHERE id = ?",
						array($parent_id, $c['id']));
				}
			}
		}
	}
}

/**
 * Get subnets as a hierarchical tree, sorted by parent-child relationships.
 * Returns flat array with 'depth' key for indentation.
 */
function cereus_ipam_get_subnets_tree($section_id = null, $parent_id = 0, $depth = 0) {
	$sql = "SELECT s.*, sec.name AS section_name,
		(SELECT COUNT(*) FROM plugin_cereus_ipam_addresses WHERE subnet_id = s.id) AS addr_count
		FROM plugin_cereus_ipam_subnets s
		LEFT JOIN plugin_cereus_ipam_sections sec ON sec.id = s.section_id
		WHERE s.parent_id = ?";
	$params = array($parent_id);

	if ($section_id !== null && $section_id >= 0) {
		$sql .= " AND s.section_id = ?";
		$params[] = $section_id;
	}

	$sql .= " ORDER BY s.subnet, s.mask";

	$subnets = db_fetch_assoc_prepared($sql, $params);

	$result = array();
	if (cacti_sizeof($subnets)) {
		foreach ($subnets as $s) {
			$s['depth'] = $depth;
			$result[] = $s;
			/* Recursively add children */
			$children = cereus_ipam_get_subnets_tree($section_id, $s['id'], $depth + 1);
			$result = array_merge($result, $children);
		}
	}
	return $result;
}

/**
 * Get subnets dropdown for parent selection (only subnets with smaller masks).
 */
function cereus_ipam_get_parent_subnets_dropdown($section_id, $current_mask = 128, $exclude_id = 0) {
	$dropdown = array(0 => __('None (Top Level)', 'cereus_ipam'));

	$candidates = db_fetch_assoc_prepared(
		"SELECT id, subnet, mask, description FROM plugin_cereus_ipam_subnets
		WHERE section_id = ? AND mask < ? AND id != ?
		ORDER BY subnet, mask",
		array($section_id, $current_mask, $exclude_id)
	);

	if (cacti_sizeof($candidates)) {
		foreach ($candidates as $c) {
			$dropdown[$c['id']] = $c['subnet'] . '/' . $c['mask'] . ' - ' . $c['description'];
		}
	}

	return $dropdown;
}

/**
 * Get subnets as a dropdown array for forms (id => "subnet/mask - description").
 */
function cereus_ipam_get_subnets_dropdown() {
	$rows = db_fetch_assoc("SELECT id, subnet, mask, description FROM plugin_cereus_ipam_subnets ORDER BY subnet, mask");
	$result = array(0 => __('None', 'cereus_ipam'));
	if (cacti_sizeof($rows)) {
		foreach ($rows as $r) {
			$result[$r['id']] = $r['subnet'] . '/' . $r['mask'] . (!empty($r['description']) ? ' - ' . $r['description'] : '');
		}
	}
	return $result;
}

/**
 * Get the tenant ID for the current user (or specific user).
 * Returns 0 if user is not assigned to any tenant.
 */
function cereus_ipam_get_user_tenant($user_id = null) {
	if ($user_id === null) {
		$user_id = isset($_SESSION['sess_user_id']) ? (int)$_SESSION['sess_user_id'] : 0;
	}

	if (!cereus_ipam_license_has_multitenancy()) {
		return 0;
	}

	$tenant_id = db_fetch_cell_prepared(
		"SELECT tenant_id FROM plugin_cereus_ipam_tenant_members WHERE user_id = ? LIMIT 1",
		array($user_id)
	);

	return $tenant_id ? (int)$tenant_id : 0;
}

/**
 * Get tenants dropdown array for filter bars.
 */
function cereus_ipam_get_tenants_dropdown() {
	$result = array('-1' => __('All Tenants', 'cereus_ipam'), '0' => __('Global (No Tenant)', 'cereus_ipam'));
	$rows = db_fetch_assoc("SELECT id, name FROM plugin_cereus_ipam_tenants WHERE enabled = 1 ORDER BY name");
	if (!cacti_sizeof($rows)) {
		return $result;
	}
	foreach ($rows as $r) {
		$result[$r['id']] = $r['name'];
	}
	return $result;
}

/**
 * Apply tenant filter to SQL WHERE clause.
 * Returns modified SQL WHERE string and updated params array.
 */
function cereus_ipam_apply_tenant_filter($sql_where, $sql_params, $tenant_id, $table_alias = 'sec') {
	if (!cereus_ipam_license_has_multitenancy()) {
		return array($sql_where, $sql_params);
	}

	if ($tenant_id == '0') {
		$sql_where .= " AND ({$table_alias}.tenant_id IS NULL OR {$table_alias}.tenant_id = 0)";
	} elseif ($tenant_id > 0) {
		$sql_where .= " AND {$table_alias}.tenant_id = ?";
		$sql_params[] = $tenant_id;
	}
	/* tenant_id == -1 means "all", no filter applied */

	return array($sql_where, $sql_params);
}

/**
 * Get all email addresses from a Cacti notification list.
 * Returns comma-separated email string or empty string.
 *
 * @param int $list_id  Notification list ID.
 * @return string       Comma-separated email addresses.
 */
function cereus_ipam_get_notification_list_emails($list_id) {
	$list_id = (int) $list_id;
	if ($list_id <= 0) {
		return '';
	}

	$emails = db_fetch_cell_prepared(
		"SELECT emails FROM plugin_notification_lists WHERE id = ?",
		array($list_id)
	);

	return $emails ?: '';
}

/**
 * Merge manual email addresses with notification list emails.
 * Removes duplicates and returns a clean comma-separated string.
 *
 * @param string $manual_emails  Comma-separated manual email addresses.
 * @param int    $list_id        Notification list ID (0 = none).
 * @return string                Merged, deduplicated, comma-separated emails.
 */
function cereus_ipam_merge_notification_emails($manual_emails, $list_id) {
	$all_emails = array();

	/* Parse manual emails */
	if (!empty($manual_emails)) {
		$parts = array_map('trim', explode(',', $manual_emails));
		foreach ($parts as $e) {
			if (!empty($e) && filter_var($e, FILTER_VALIDATE_EMAIL)) {
				$all_emails[strtolower($e)] = $e;
			}
		}
	}

	/* Get notification list emails */
	$list_emails = cereus_ipam_get_notification_list_emails($list_id);
	if (!empty($list_emails)) {
		$parts = array_map('trim', explode(',', $list_emails));
		foreach ($parts as $e) {
			if (!empty($e) && filter_var($e, FILTER_VALIDATE_EMAIL)) {
				$all_emails[strtolower($e)] = $e;
			}
		}
	}

	return implode(',', $all_emails);
}

/**
 * Lookup DNS hostname for an IP (reverse lookup).
 */
function cereus_ipam_dns_reverse($ip) {
	$host = @gethostbyaddr($ip);
	if ($host === $ip || $host === false) {
		return '';
	}
	return $host;
}

/**
 * Lookup IP for a hostname (forward lookup).
 */
function cereus_ipam_dns_forward($hostname) {
	$ip = @gethostbyname($hostname);
	if ($ip === $hostname) {
		return '';
	}
	return $ip;
}

/**
 * Get all locations as a flat list with depth indicator for hierarchy display.
 * Returns flat array with 'depth' key for indentation.
 */
function cereus_ipam_get_locations_tree($parent_id = 0, $depth = 0) {
	$locations = db_fetch_assoc_prepared(
		"SELECT * FROM plugin_cereus_ipam_locations
		WHERE parent_id = ? ORDER BY display_order, name",
		array($parent_id)
	);

	$result = array();
	if (cacti_sizeof($locations)) {
		foreach ($locations as $loc) {
			$loc['depth'] = $depth;
			$result[] = $loc;
			$children = cereus_ipam_get_locations_tree($loc['id'], $depth + 1);
			$result = array_merge($result, $children);
		}
	}
	return $result;
}

/**
 * Get locations as a dropdown array with indentation.
 * Returns array(id => indented name) suitable for form dropdowns.
 */
function cereus_ipam_get_locations_dropdown() {
	$tree = cereus_ipam_get_locations_tree();
	$dropdown = array(0 => __('None', 'cereus_ipam'));
	foreach ($tree as $loc) {
		$prefix = str_repeat('-- ', $loc['depth']);
		$type_label = !empty($loc['type']) ? ' [' . ucfirst($loc['type']) . ']' : '';
		$dropdown[$loc['id']] = $prefix . $loc['name'] . $type_label;
	}
	return $dropdown;
}

/* ==================== Tag Functions ==================== */

/**
 * Get all tags as array.
 */
function cereus_ipam_get_all_tags() {
	return db_fetch_assoc("SELECT * FROM plugin_cereus_ipam_tags ORDER BY name");
}

/**
 * Get tags assigned to a specific object.
 *
 * @param string $object_type 'subnet' or 'address'
 * @param int    $object_id
 * @return array of tag rows
 */
function cereus_ipam_get_object_tags($object_type, $object_id) {
	return db_fetch_assoc_prepared(
		"SELECT t.* FROM plugin_cereus_ipam_tags t
		 INNER JOIN plugin_cereus_ipam_tag_assignments ta ON ta.tag_id = t.id
		 WHERE ta.object_type = ? AND ta.object_id = ?
		 ORDER BY t.name",
		array($object_type, $object_id)
	);
}

/**
 * Save tag assignments for an object. Replaces all existing assignments.
 *
 * @param string $object_type 'subnet' or 'address'
 * @param int    $object_id
 * @param array  $tag_ids     Array of tag IDs to assign
 */
function cereus_ipam_save_object_tags($object_type, $object_id, $tag_ids) {
	db_execute_prepared(
		"DELETE FROM plugin_cereus_ipam_tag_assignments WHERE object_type = ? AND object_id = ?",
		array($object_type, $object_id)
	);

	if (cacti_sizeof($tag_ids)) {
		foreach ($tag_ids as $tag_id) {
			$tag_id = (int) $tag_id;
			if ($tag_id > 0) {
				db_execute_prepared(
					"INSERT IGNORE INTO plugin_cereus_ipam_tag_assignments (tag_id, object_type, object_id) VALUES (?, ?, ?)",
					array($tag_id, $object_type, $object_id)
				);
			}
		}
	}
}

/**
 * Render tag badges as HTML for display in list views.
 *
 * @param array $tags Array of tag rows (id, name, color)
 * @return string HTML
 */
function cereus_ipam_render_tag_badges($tags) {
	if (!cacti_sizeof($tags)) {
		return '';
	}

	$html = '';
	foreach ($tags as $tag) {
		$bg = html_escape($tag['color']);
		$name = html_escape($tag['name']);
		/* Determine text color based on background brightness */
		$r = hexdec(substr($bg, 1, 2));
		$g = hexdec(substr($bg, 3, 2));
		$b = hexdec(substr($bg, 5, 2));
		$text_color = (($r * 299 + $g * 587 + $b * 114) / 1000) > 128 ? '#000' : '#fff';
		$html .= '<span style="display:inline-block;padding:1px 6px;margin:1px 2px;border-radius:3px;font-size:11px;'
			. 'background-color:' . $bg . ';color:' . $text_color . ';">' . $name . '</span>';
	}
	return $html;
}

/**
 * Get tags dropdown array for form select elements.
 *
 * @return array tag_id => name
 */
function cereus_ipam_get_tags_dropdown() {
	$tags = db_fetch_assoc("SELECT id, name FROM plugin_cereus_ipam_tags ORDER BY name");
	$dropdown = array();
	if (cacti_sizeof($tags)) {
		foreach ($tags as $t) {
			$dropdown[$t['id']] = $t['name'];
		}
	}
	return $dropdown;
}

/**
 * Bulk-fetch tags for a list of object IDs. Returns array keyed by object_id.
 *
 * @param string $object_type 'subnet' or 'address'
 * @param array  $object_ids
 * @return array object_id => array of tag rows
 */
function cereus_ipam_get_bulk_tags($object_type, $object_ids) {
	$result = array();
	if (!cacti_sizeof($object_ids)) {
		return $result;
	}

	$placeholders = implode(',', array_fill(0, count($object_ids), '?'));
	$params = array_merge(array($object_type), $object_ids);

	$rows = db_fetch_assoc_prepared(
		"SELECT ta.object_id, t.id, t.name, t.color
		 FROM plugin_cereus_ipam_tag_assignments ta
		 INNER JOIN plugin_cereus_ipam_tags t ON t.id = ta.tag_id
		 WHERE ta.object_type = ? AND ta.object_id IN ($placeholders)
		 ORDER BY t.name",
		$params
	);

	if (cacti_sizeof($rows)) {
		foreach ($rows as $row) {
			$oid = $row['object_id'];
			if (!isset($result[$oid])) {
				$result[$oid] = array();
			}
			$result[$oid][] = $row;
		}
	}
	return $result;
}
