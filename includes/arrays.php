<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2024-2026 Urban-Software.de / Thomas Urban               |
 +-------------------------------------------------------------------------+
 | Cereus IPAM - Config Arrays (menu, realms)                              |
 +-------------------------------------------------------------------------+
*/

function cereus_ipam_config_arrays() {
	global $user_auth_realm_filenames, $menu;

	/* map realm ID to filenames */
	$realm_id_manage = db_fetch_cell_prepared("SELECT id FROM plugin_realms WHERE plugin = 'cereus_ipam' AND display LIKE '%Manage%'");

	if (!empty($realm_id_manage)) {
		$realm_id_manage += 100;
		$user_auth_realm_filenames['cereus_ipam.php']           = $realm_id_manage;
		$user_auth_realm_filenames['cereus_ipam_addresses.php'] = $realm_id_manage;
		$user_auth_realm_filenames['cereus_ipam_vlans.php']     = $realm_id_manage;
		$user_auth_realm_filenames['cereus_ipam_changelog.php'] = $realm_id_manage;
		$user_auth_realm_filenames['cereus_ipam_import.php']    = $realm_id_manage;
		$user_auth_realm_filenames['cereus_ipam_scan.php']      = $realm_id_manage;
		$user_auth_realm_filenames['cereus_ipam_vrfs.php']     = $realm_id_manage;
		$user_auth_realm_filenames['cereus_ipam_customfields.php'] = $realm_id_manage;
		$user_auth_realm_filenames['cereus_ipam_reports.php']       = $realm_id_manage;
		$user_auth_realm_filenames['cereus_ipam_maintenance.php']   = $realm_id_manage;
		$user_auth_realm_filenames['cereus_ipam_calculator.php']   = $realm_id_manage;
		$user_auth_realm_filenames['cereus_ipam_dhcp.php']         = $realm_id_manage;
		$user_auth_realm_filenames['cereus_ipam_tenants.php']      = $realm_id_manage;
		$user_auth_realm_filenames['cereus_ipam_locations.php']    = $realm_id_manage;
		$user_auth_realm_filenames['cereus_ipam_dashboard.php']    = $realm_id_manage;
		$user_auth_realm_filenames['cereus_ipam_search.php']       = $realm_id_manage;
		$user_auth_realm_filenames['cereus_ipam_tags.php']         = $realm_id_manage;
	}

	/* add menu items under Cereus Tools */
	$menu[__('Cereus Tools')]['plugins/cereus_ipam/cereus_ipam_dashboard.php']  = __('IPAM &mdash; Dashboard', 'cereus_ipam');
	$menu[__('Cereus Tools')]['plugins/cereus_ipam/cereus_ipam_search.php']    = __('IPAM &mdash; Search', 'cereus_ipam');
	$menu[__('Cereus Tools')]['plugins/cereus_ipam/cereus_ipam.php']           = __('IPAM &mdash; Subnets', 'cereus_ipam');
	$menu[__('Cereus Tools')]['plugins/cereus_ipam/cereus_ipam_vlans.php']     = __('IPAM &mdash; VLANs', 'cereus_ipam');
	$menu[__('Cereus Tools')]['plugins/cereus_ipam/cereus_ipam_vrfs.php']      = __('IPAM &mdash; VRFs', 'cereus_ipam');
	$menu[__('Cereus Tools')]['plugins/cereus_ipam/cereus_ipam_reports.php']      = __('IPAM &mdash; Reports', 'cereus_ipam');
	$menu[__('Cereus Tools')]['plugins/cereus_ipam/cereus_ipam_changelog.php'] = __('IPAM &mdash; Changelog', 'cereus_ipam');
	$menu[__('Cereus Tools')]['plugins/cereus_ipam/cereus_ipam_maintenance.php'] = __('IPAM &mdash; Maintenance', 'cereus_ipam');
	$menu[__('Cereus Tools')]['plugins/cereus_ipam/cereus_ipam_calculator.php'] = __('IPAM &mdash; Calculator', 'cereus_ipam');
	$menu[__('Cereus Tools')]['plugins/cereus_ipam/cereus_ipam_dhcp.php']       = __('IPAM &mdash; DHCP Scopes', 'cereus_ipam');
	$menu[__('Cereus Tools')]['plugins/cereus_ipam/cereus_ipam_tenants.php']   = __('IPAM &mdash; Tenants', 'cereus_ipam');
	$menu[__('Cereus Tools')]['plugins/cereus_ipam/cereus_ipam_locations.php'] = __('IPAM &mdash; Locations', 'cereus_ipam');
	$menu[__('Cereus Tools')]['plugins/cereus_ipam/cereus_ipam_tags.php']      = __('IPAM &mdash; Tags', 'cereus_ipam');
}
