<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2024-2026 Urban-Software.de / Thomas Urban               |
 +-------------------------------------------------------------------------+
 | Cereus IPAM - License Check (wraps cereus_license plugin)               |
 +-------------------------------------------------------------------------+
*/

if (function_exists('cereus_ipam_license_tier')) {
	return;
}

/**
 * Get current license tier for cereus_ipam.
 * Falls back to 'community' if cereus_license plugin is not installed.
 */
function cereus_ipam_license_tier() {
	if (function_exists('cereus_license_get_tier')) {
		$tier = cereus_license_get_tier('cereus_ipam');
		if ($tier === 'unlicensed') {
			return 'community';
		}
		return $tier;
	}
	return 'community';
}

/**
 * Check if current tier meets minimum requirement.
 */
function cereus_ipam_license_at_least($minimum) {
	$tiers = array('community' => 0, 'professional' => 1, 'enterprise' => 2);
	$current = cereus_ipam_license_tier();
	return (isset($tiers[$current]) ? $tiers[$current] : 0) >= (isset($tiers[$minimum]) ? $tiers[$minimum] : 0);
}

/**
 * Check a specific feature flag.
 */
function cereus_ipam_license_has_feature($feature) {
	if (function_exists('cereus_license_check_feature')) {
		return cereus_license_check_feature('cereus_ipam', $feature);
	}
	return false;
}

/* --- Feature checks --- */

/**
 * Max subnets allowed.
 * Community: 10, Professional+: unlimited (0 = unlimited)
 */
function cereus_ipam_license_max_subnets() {
	if (cereus_ipam_license_at_least('professional')) {
		return 0;
	}
	return CEREUS_IPAM_COMMUNITY_MAX_SUBNETS;
}

/**
 * Current subnet count.
 */
function cereus_ipam_license_subnet_count() {
	return (int) db_fetch_cell("SELECT COUNT(*) FROM plugin_cereus_ipam_subnets");
}

/**
 * IPv6 support requires Professional+.
 */
function cereus_ipam_license_has_ipv6() {
	return cereus_ipam_license_at_least('professional');
}

/**
 * VLAN management requires Professional+.
 */
function cereus_ipam_license_has_vlans() {
	return cereus_ipam_license_at_least('professional');
}

/**
 * VRF support requires Professional+.
 */
function cereus_ipam_license_has_vrfs() {
	return cereus_ipam_license_at_least('professional');
}

/**
 * Network scanning requires Professional+.
 */
function cereus_ipam_license_has_scanning() {
	return cereus_ipam_license_at_least('professional');
}

/**
 * Custom fields require Professional+.
 */
function cereus_ipam_license_has_custom_fields() {
	return cereus_ipam_license_at_least('professional');
}

/**
 * Advanced search (regex, custom field filters) requires Professional+.
 */
function cereus_ipam_license_has_advanced_search() {
	return cereus_ipam_license_at_least('professional');
}

/**
 * Per-section RBAC requires Professional+.
 */
function cereus_ipam_license_has_rbac() {
	return cereus_ipam_license_at_least('professional');
}

/**
 * Threshold alerts require Professional+.
 */
function cereus_ipam_license_has_threshold_alerts() {
	return cereus_ipam_license_at_least('professional');
}

/**
 * NAT mapping requires Professional+.
 */
function cereus_ipam_license_has_nat() {
	return cereus_ipam_license_at_least('professional');
}

/**
 * DNS integration requires Professional+.
 */
function cereus_ipam_license_has_dns() {
	return cereus_ipam_license_at_least('professional');
}

/**
 * Max CSV import rows.
 * Community: 500, Professional+: unlimited (0)
 */
function cereus_ipam_license_max_import_rows() {
	if (cereus_ipam_license_at_least('professional')) {
		return 0;
	}
	return CEREUS_IPAM_COMMUNITY_MAX_IMPORT_ROWS;
}

/**
 * Changelog retention in days.
 * Community: 30, Professional+: unlimited (0)
 */
function cereus_ipam_license_log_retention() {
	if (cereus_ipam_license_at_least('professional')) {
		return 0;
	}
	return CEREUS_IPAM_COMMUNITY_LOG_RETENTION;
}

/**
 * LDAP/AD integration requires Enterprise.
 */
function cereus_ipam_license_has_ldap() {
	return cereus_ipam_license_at_least('enterprise');
}

/**
 * Multi-tenancy requires Enterprise.
 */
function cereus_ipam_license_has_multitenancy() {
	return cereus_ipam_license_at_least('enterprise');
}

/**
 * DHCP scope monitoring requires Enterprise.
 */
function cereus_ipam_license_has_dhcp_monitoring() {
	return cereus_ipam_license_at_least('enterprise');
}

/**
 * Automated reconciliation requires Enterprise.
 */
function cereus_ipam_license_has_reconciliation() {
	return cereus_ipam_license_at_least('enterprise');
}

/**
 * Webhook callbacks require Enterprise.
 */
function cereus_ipam_license_has_webhooks() {
	return cereus_ipam_license_at_least('enterprise');
}

/**
 * REST API endpoints require Enterprise.
 */
function cereus_ipam_license_has_restapi() {
	return cereus_ipam_license_at_least('enterprise');
}

/**
 * Maintenance windows require Enterprise.
 */
function cereus_ipam_license_has_maintenance() {
	return cereus_ipam_license_at_least('enterprise');
}

/**
 * Rack/Location visualization requires Enterprise.
 */
function cereus_ipam_license_has_locations() {
	return cereus_ipam_license_at_least('enterprise');
}

/**
 * Conflict detection alerts require Professional+.
 */
function cereus_ipam_license_has_conflict_alerts() {
	return cereus_ipam_license_at_least('professional');
}

/**
 * Scheduled report email delivery requires Professional+.
 */
function cereus_ipam_license_has_scheduled_reports() {
	return cereus_ipam_license_at_least('professional');
}

/**
 * Reports (utilization, states, stale, reconciliation) require Professional+.
 */
function cereus_ipam_license_has_reports() {
	return cereus_ipam_license_at_least('professional');
}

/**
 * Capacity forecasting requires Enterprise.
 */
function cereus_ipam_license_has_forecasting() {
	return cereus_ipam_license_at_least('enterprise');
}

/**
 * Subnet nesting/hierarchy requires Professional+.
 */
function cereus_ipam_license_has_subnet_nesting() {
	return cereus_ipam_license_at_least('professional');
}

/**
 * Bulk IP range fill requires Professional+.
 */
function cereus_ipam_license_has_bulk_fill() {
	return cereus_ipam_license_at_least('professional');
}

/**
 * Visual network map (tile map) requires Professional+.
 */
function cereus_ipam_license_has_visual_map() {
	return cereus_ipam_license_at_least('professional');
}

/**
 * Hilbert curve heatmap requires Enterprise.
 */
function cereus_ipam_license_has_hilbert_map() {
	return cereus_ipam_license_at_least('enterprise');
}
