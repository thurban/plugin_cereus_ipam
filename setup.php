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
 | Cereus IPAM - Plugin Setup                                              |
 +-------------------------------------------------------------------------+
*/

function plugin_cereus_ipam_install() {
	/* UI hooks */
	api_plugin_register_hook('cereus_ipam', 'config_arrays',        'cereus_ipam_config_arrays',   'includes/arrays.php');
	api_plugin_register_hook('cereus_ipam', 'config_settings',      'cereus_ipam_config_settings', 'includes/settings.php');
	api_plugin_register_hook('cereus_ipam', 'draw_navigation_text', 'cereus_ipam_draw_navigation', 'setup.php');

	/* settings_bottom hook for injecting JS on settings page (works with AJAX nav) */
	api_plugin_register_hook('cereus_ipam', 'settings_bottom', 'cereus_ipam_settings_bottom', 'setup.php');

	/* poller hook for device sync and scheduled scans */
	api_plugin_register_hook('cereus_ipam', 'poller_bottom', 'cereus_ipam_poller_bottom', 'setup.php');

	/* REST API endpoints (via restapi plugin) */
	api_plugin_register_hook('cereus_ipam', 'restapi_register_endpoints', 'cereus_ipam_restapi_endpoints', 'lib/restapi_endpoints.php');

	/* Device page integration */
	api_plugin_register_hook('cereus_ipam', 'device_edit_pre_bottom', 'cereus_ipam_device_edit_pre_bottom', 'setup.php');
	api_plugin_register_hook('cereus_ipam', 'device_display_text',    'cereus_ipam_device_display_text',    'setup.php');
	api_plugin_register_hook('cereus_ipam', 'device_table_replace',   'cereus_ipam_device_table_replace',   'setup.php');

	/* realms */
	api_plugin_register_realm('cereus_ipam', 'cereus_ipam.php,cereus_ipam_addresses.php,cereus_ipam_vlans.php,cereus_ipam_vrfs.php,cereus_ipam_customfields.php,cereus_ipam_reports.php,cereus_ipam_changelog.php,cereus_ipam_import.php,cereus_ipam_scan.php,cereus_ipam_maintenance.php,cereus_ipam_calculator.php,cereus_ipam_dhcp.php,cereus_ipam_tenants.php,cereus_ipam_locations.php,cereus_ipam_dashboard.php', __('Plugin: Cereus IPAM - Manage', 'cereus_ipam'), 1);

	/* tables */
	cereus_ipam_setup_tables();
}

function plugin_cereus_ipam_uninstall() {
	db_execute("DROP TABLE IF EXISTS plugin_cereus_ipam_tag_assignments");
	db_execute("DROP TABLE IF EXISTS plugin_cereus_ipam_tags");
	db_execute("DROP TABLE IF EXISTS plugin_cereus_ipam_conflicts");
	db_execute("DROP TABLE IF EXISTS plugin_cereus_ipam_locations");
	db_execute("DROP TABLE IF EXISTS plugin_cereus_ipam_tenant_members");
	db_execute("DROP TABLE IF EXISTS plugin_cereus_ipam_tenants");
	db_execute("DROP TABLE IF EXISTS plugin_cereus_ipam_maintenance");
	db_execute("DROP TABLE IF EXISTS plugin_cereus_ipam_utilization_history");
	db_execute("DROP TABLE IF EXISTS plugin_cereus_ipam_dhcp_scopes");
	db_execute("DROP TABLE IF EXISTS plugin_cereus_ipam_scan_results");
	db_execute("DROP TABLE IF EXISTS plugin_cereus_ipam_changelog");
	db_execute("DROP TABLE IF EXISTS plugin_cereus_ipam_custom_fields");
	db_execute("DROP TABLE IF EXISTS plugin_cereus_ipam_addresses");
	db_execute("DROP TABLE IF EXISTS plugin_cereus_ipam_subnets");
	db_execute("DROP TABLE IF EXISTS plugin_cereus_ipam_vlans");
	db_execute("DROP TABLE IF EXISTS plugin_cereus_ipam_vrfs");
	db_execute("DROP TABLE IF EXISTS plugin_cereus_ipam_sections");
}

function plugin_cereus_ipam_version() {
	return array(
		'name'     => 'cereus_ipam',
		'version'  => '1.0.0',
		'longname' => 'Cereus IPAM',
		'author'   => 'Urban-Software.de / Thomas Urban',
		'homepage' => 'https://www.urban-software.com',
		'email'    => 'info@urban-software.de',
		'url'      => 'https://www.urban-software.com',
	);
}

function plugin_cereus_ipam_check_config() {
	return true;
}

function plugin_cereus_ipam_upgrade($info) {
	return false;
}

/* ==================== Table Creation ==================== */

function cereus_ipam_setup_tables() {
	db_execute("CREATE TABLE IF NOT EXISTS plugin_cereus_ipam_sections (
		id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		parent_id      BIGINT UNSIGNED NOT NULL DEFAULT 0,
		name           VARCHAR(255) NOT NULL,
		description    TEXT,
		permissions    TEXT,
		display_order  INT NOT NULL DEFAULT 0,
		created        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		modified       TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		PRIMARY KEY (id),
		KEY idx_parent (parent_id)
	) ENGINE=InnoDB ROW_FORMAT=Dynamic DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

	db_execute("CREATE TABLE IF NOT EXISTS plugin_cereus_ipam_subnets (
		id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		section_id     BIGINT UNSIGNED NOT NULL,
		parent_id      BIGINT UNSIGNED NOT NULL DEFAULT 0,
		subnet         VARCHAR(45) NOT NULL,
		mask           TINYINT UNSIGNED NOT NULL,
		vlan_id        BIGINT UNSIGNED DEFAULT NULL,
		vrf_id         BIGINT UNSIGNED DEFAULT NULL,
		description    VARCHAR(255) DEFAULT '',
		gateway        VARCHAR(45) DEFAULT NULL,
		nameservers    VARCHAR(512) DEFAULT NULL,
		threshold_pct  TINYINT UNSIGNED DEFAULT 90,
		scan_enabled   TINYINT(1) NOT NULL DEFAULT 0,
		scan_interval  INT UNSIGNED DEFAULT 3600,
		last_scanned   TIMESTAMP NULL,
		show_name      TINYINT(1) NOT NULL DEFAULT 1,
		is_pool        TINYINT(1) NOT NULL DEFAULT 0,
		custom_fields  JSON,
		created        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		modified       TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		PRIMARY KEY (id),
		KEY idx_section (section_id),
		KEY idx_parent (parent_id),
		KEY idx_subnet_mask (subnet, mask),
		KEY idx_vlan (vlan_id),
		KEY idx_vrf (vrf_id)
	) ENGINE=InnoDB ROW_FORMAT=Dynamic DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

	db_execute("CREATE TABLE IF NOT EXISTS plugin_cereus_ipam_addresses (
		id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		subnet_id       BIGINT UNSIGNED NOT NULL,
		ip              VARCHAR(45) NOT NULL,
		hostname        VARCHAR(255) DEFAULT NULL,
		description     VARCHAR(255) DEFAULT NULL,
		mac_address     VARCHAR(17) DEFAULT NULL,
		owner           VARCHAR(255) DEFAULT NULL,
		device_type     VARCHAR(128) DEFAULT NULL,
		device_location VARCHAR(255) DEFAULT NULL,
		state           ENUM('active','reserved','dhcp','offline','available') NOT NULL DEFAULT 'available',
		cacti_host_id   INT UNSIGNED DEFAULT NULL,
		nat_inside      VARCHAR(45) DEFAULT NULL,
		nat_outside     VARCHAR(45) DEFAULT NULL,
		last_seen       TIMESTAMP NULL,
		port            VARCHAR(64) DEFAULT NULL,
		note            TEXT,
		custom_fields   JSON,
		created_by      INT UNSIGNED DEFAULT NULL,
		created         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		modified        TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		PRIMARY KEY (id),
		UNIQUE KEY idx_subnet_ip (subnet_id, ip),
		KEY idx_ip (ip),
		KEY idx_hostname (hostname),
		KEY idx_mac (mac_address),
		KEY idx_state (state),
		KEY idx_cacti_host (cacti_host_id),
		KEY idx_last_seen (last_seen)
	) ENGINE=InnoDB ROW_FORMAT=Dynamic DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

	db_execute("CREATE TABLE IF NOT EXISTS plugin_cereus_ipam_vlans (
		id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		vlan_number INT UNSIGNED NOT NULL,
		name        VARCHAR(255) NOT NULL,
		description TEXT,
		domain_id   BIGINT UNSIGNED DEFAULT NULL,
		custom_fields JSON,
		created     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		modified    TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		PRIMARY KEY (id),
		UNIQUE KEY idx_domain_vlan (domain_id, vlan_number)
	) ENGINE=InnoDB ROW_FORMAT=Dynamic DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

	db_execute("CREATE TABLE IF NOT EXISTS plugin_cereus_ipam_vrfs (
		id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		name        VARCHAR(255) NOT NULL,
		rd          VARCHAR(32) DEFAULT NULL,
		description TEXT,
		created     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		modified    TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		PRIMARY KEY (id),
		UNIQUE KEY idx_rd (rd)
	) ENGINE=InnoDB ROW_FORMAT=Dynamic DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

	db_execute("CREATE TABLE IF NOT EXISTS plugin_cereus_ipam_custom_fields (
		id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		name          VARCHAR(64) NOT NULL,
		label         VARCHAR(255) NOT NULL,
		type          ENUM('text','textarea','dropdown','checkbox','date','url') NOT NULL DEFAULT 'text',
		options       TEXT,
		applies_to    ENUM('subnet','address','vlan') NOT NULL,
		required      TINYINT(1) NOT NULL DEFAULT 0,
		display_order INT NOT NULL DEFAULT 0,
		created       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (id),
		UNIQUE KEY idx_name_applies (name, applies_to)
	) ENGINE=InnoDB ROW_FORMAT=Dynamic DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

	db_execute("CREATE TABLE IF NOT EXISTS plugin_cereus_ipam_changelog (
		id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		user_id     INT UNSIGNED NOT NULL,
		action      ENUM('create','update','delete','import','scan','truncate') NOT NULL,
		object_type ENUM('section','subnet','address','vlan','vrf','custom_field','setting') NOT NULL,
		object_id   BIGINT UNSIGNED NOT NULL,
		old_value   JSON,
		new_value   JSON,
		ip_address  VARCHAR(45) DEFAULT NULL,
		created     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (id),
		KEY idx_object (object_type, object_id),
		KEY idx_user (user_id),
		KEY idx_created (created)
	) ENGINE=InnoDB ROW_FORMAT=Dynamic DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

	db_execute("CREATE TABLE IF NOT EXISTS plugin_cereus_ipam_scan_results (
		id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		subnet_id  BIGINT UNSIGNED NOT NULL,
		ip         VARCHAR(45) NOT NULL,
		is_alive   TINYINT(1) NOT NULL DEFAULT 0,
		hostname   VARCHAR(255) DEFAULT NULL,
		mac_address VARCHAR(17) DEFAULT NULL,
		scan_type  ENUM('ping','arp','snmp','dns') NOT NULL,
		scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (id),
		KEY idx_subnet (subnet_id),
		KEY idx_ip (ip),
		KEY idx_scanned (scanned_at)
	) ENGINE=InnoDB ROW_FORMAT=Dynamic DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

	db_execute("CREATE TABLE IF NOT EXISTS plugin_cereus_ipam_utilization_history (
		id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		subnet_id   BIGINT UNSIGNED NOT NULL,
		used        INT UNSIGNED NOT NULL DEFAULT 0,
		total       INT UNSIGNED NOT NULL DEFAULT 0,
		pct         TINYINT UNSIGNED NOT NULL DEFAULT 0,
		recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (id),
		KEY idx_subnet_time (subnet_id, recorded_at),
		KEY idx_recorded (recorded_at)
	) ENGINE=InnoDB ROW_FORMAT=Dynamic DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

	db_execute("CREATE TABLE IF NOT EXISTS plugin_cereus_ipam_maintenance (
		id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		title           VARCHAR(255) NOT NULL,
		description     TEXT,
		start_time      DATETIME NOT NULL,
		end_time        DATETIME NOT NULL,
		subnet_ids      TEXT,
		suppress_scans  TINYINT(1) NOT NULL DEFAULT 1,
		suppress_alerts TINYINT(1) NOT NULL DEFAULT 1,
		created_by      INT UNSIGNED DEFAULT NULL,
		created         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (id),
		KEY idx_time (start_time, end_time)
	) ENGINE=InnoDB ROW_FORMAT=Dynamic DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

	db_execute("CREATE TABLE IF NOT EXISTS plugin_cereus_ipam_locations (
		id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		parent_id   BIGINT UNSIGNED NOT NULL DEFAULT 0,
		name        VARCHAR(255) NOT NULL,
		description TEXT,
		type        ENUM('site','building','floor','room','rack') NOT NULL DEFAULT 'site',
		display_order INT NOT NULL DEFAULT 0,
		created     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		modified    TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		PRIMARY KEY (id),
		KEY idx_parent (parent_id),
		KEY idx_type (type)
	) ENGINE=InnoDB ROW_FORMAT=Dynamic DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

	db_execute("CREATE TABLE IF NOT EXISTS plugin_cereus_ipam_tenants (
		id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		name        VARCHAR(255) NOT NULL,
		description TEXT,
		enabled     TINYINT(1) NOT NULL DEFAULT 1,
		created     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		modified    TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		PRIMARY KEY (id),
		UNIQUE KEY idx_name (name)
	) ENGINE=InnoDB ROW_FORMAT=Dynamic DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

	db_execute("CREATE TABLE IF NOT EXISTS plugin_cereus_ipam_tenant_members (
		tenant_id   BIGINT UNSIGNED NOT NULL,
		user_id     INT UNSIGNED NOT NULL,
		PRIMARY KEY (tenant_id, user_id),
		KEY idx_user (user_id)
	) ENGINE=InnoDB ROW_FORMAT=Dynamic DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

	/* Add tenant_id to sections if not exists */
	$cols = db_fetch_assoc("SHOW COLUMNS FROM plugin_cereus_ipam_sections LIKE 'tenant_id'");
	if (!cacti_sizeof($cols)) {
		db_execute("ALTER TABLE plugin_cereus_ipam_sections ADD COLUMN tenant_id BIGINT UNSIGNED DEFAULT NULL AFTER parent_id, ADD KEY idx_tenant (tenant_id)");
	}

	/* Add location_id to addresses if not exists */
	$cols = db_fetch_assoc("SHOW COLUMNS FROM plugin_cereus_ipam_addresses LIKE 'location_id'");
	if (!cacti_sizeof($cols)) {
		db_execute("ALTER TABLE plugin_cereus_ipam_addresses ADD COLUMN location_id BIGINT UNSIGNED DEFAULT NULL AFTER device_location, ADD KEY idx_location (location_id)");
	}

	db_execute("CREATE TABLE IF NOT EXISTS plugin_cereus_ipam_dhcp_scopes (
		id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		subnet_id       BIGINT UNSIGNED NOT NULL,
		server_host_id  INT UNSIGNED DEFAULT NULL,
		server_ip       VARCHAR(45) NOT NULL,
		scope_name      VARCHAR(255) DEFAULT '',
		oid_active      VARCHAR(255) DEFAULT '.1.3.6.1.4.1.311.1.3.2.1.1.2',
		oid_total       VARCHAR(255) DEFAULT '.1.3.6.1.4.1.311.1.3.2.1.1.3',
		oid_free        VARCHAR(255) DEFAULT '.1.3.6.1.4.1.311.1.3.2.1.1.4',
		active_leases   INT UNSIGNED DEFAULT 0,
		total_leases    INT UNSIGNED DEFAULT 0,
		free_leases     INT UNSIGNED DEFAULT 0,
		last_polled     TIMESTAMP NULL,
		poll_interval   INT UNSIGNED DEFAULT 300,
		enabled         TINYINT(1) NOT NULL DEFAULT 1,
		created         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		modified        TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		PRIMARY KEY (id),
		KEY idx_subnet (subnet_id),
		KEY idx_server (server_host_id)
	) ENGINE=InnoDB ROW_FORMAT=Dynamic DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

	/* Conflicts table (v1.1) */
	db_execute("CREATE TABLE IF NOT EXISTS plugin_cereus_ipam_conflicts (
		id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		subnet_id       BIGINT UNSIGNED NOT NULL,
		ip              VARCHAR(45) NOT NULL,
		type            ENUM('mac_conflict','rogue','stale') NOT NULL,
		details         JSON,
		detected_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		resolved_at     TIMESTAMP NULL,
		resolved_by     INT UNSIGNED DEFAULT NULL,
		PRIMARY KEY (id),
		KEY idx_subnet (subnet_id),
		KEY idx_type (type),
		KEY idx_unresolved (resolved_at, subnet_id),
		KEY idx_ip (ip)
	) ENGINE=InnoDB ROW_FORMAT=Dynamic DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

	db_execute("CREATE TABLE IF NOT EXISTS plugin_cereus_ipam_tags (
		id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		name            VARCHAR(64) NOT NULL,
		color           VARCHAR(7) NOT NULL DEFAULT '#6c757d',
		description     VARCHAR(255) DEFAULT '',
		created         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (id),
		UNIQUE KEY idx_name (name)
	) ENGINE=InnoDB ROW_FORMAT=Dynamic DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

	db_execute("CREATE TABLE IF NOT EXISTS plugin_cereus_ipam_tag_assignments (
		tag_id          BIGINT UNSIGNED NOT NULL,
		object_type     ENUM('subnet','address') NOT NULL,
		object_id       BIGINT UNSIGNED NOT NULL,
		PRIMARY KEY (tag_id, object_type, object_id),
		KEY idx_object (object_type, object_id),
		KEY idx_tag (tag_id)
	) ENGINE=InnoDB ROW_FORMAT=Dynamic DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
}

/* ==================== Navigation ==================== */

function cereus_ipam_draw_navigation($nav) {
	$nav['cereus_ipam_dashboard.php:']      = array('title' => __('IPAM Dashboard', 'cereus_ipam'),    'mapping' => 'index.php:', 'url' => 'cereus_ipam_dashboard.php',      'level' => '1');
	$nav['cereus_ipam.php:']                = array('title' => __('IPAM Subnets', 'cereus_ipam'),      'mapping' => 'index.php:', 'url' => 'cereus_ipam.php',                'level' => '1');
	$nav['cereus_ipam.php:edit']            = array('title' => __('(Edit)', 'cereus_ipam'),             'mapping' => 'index.php:,cereus_ipam.php:', 'url' => '',              'level' => '2');
	$nav['cereus_ipam.php:section_edit']    = array('title' => __('(Edit Section)', 'cereus_ipam'),     'mapping' => 'index.php:,cereus_ipam.php:', 'url' => '',              'level' => '2');
	$nav['cereus_ipam_addresses.php:']      = array('title' => __('IP Addresses', 'cereus_ipam'),       'mapping' => 'index.php:,cereus_ipam.php:', 'url' => 'cereus_ipam_addresses.php', 'level' => '2');
	$nav['cereus_ipam_addresses.php:edit']  = array('title' => __('(Edit)', 'cereus_ipam'),             'mapping' => 'index.php:,cereus_ipam.php:,cereus_ipam_addresses.php:', 'url' => '', 'level' => '3');
	$nav['cereus_ipam_vlans.php:']          = array('title' => __('VLANs', 'cereus_ipam'),              'mapping' => 'index.php:', 'url' => 'cereus_ipam_vlans.php',          'level' => '1');
	$nav['cereus_ipam_vlans.php:edit']      = array('title' => __('(Edit)', 'cereus_ipam'),             'mapping' => 'index.php:,cereus_ipam_vlans.php:', 'url' => '',        'level' => '2');
	$nav['cereus_ipam_vrfs.php:']           = array('title' => __('VRFs', 'cereus_ipam'),               'mapping' => 'index.php:', 'url' => 'cereus_ipam_vrfs.php',           'level' => '1');
	$nav['cereus_ipam_vrfs.php:edit']       = array('title' => __('(Edit)', 'cereus_ipam'),             'mapping' => 'index.php:,cereus_ipam_vrfs.php:', 'url' => '',         'level' => '2');
	$nav['cereus_ipam_customfields.php:']     = array('title' => __('Custom Fields', 'cereus_ipam'),     'mapping' => 'index.php:', 'url' => 'cereus_ipam_customfields.php', 'level' => '1');
	$nav['cereus_ipam_customfields.php:edit'] = array('title' => __('(Edit)', 'cereus_ipam'),            'mapping' => 'index.php:,cereus_ipam_customfields.php:', 'url' => '', 'level' => '2');
	$nav['cereus_ipam_reports.php:']          = array('title' => __('IPAM Reports', 'cereus_ipam'),      'mapping' => 'index.php:', 'url' => 'cereus_ipam_reports.php', 'level' => '1');
	$nav['cereus_ipam_changelog.php:']      = array('title' => __('IPAM Changelog', 'cereus_ipam'),     'mapping' => 'index.php:', 'url' => 'cereus_ipam_changelog.php',      'level' => '1');
	$nav['cereus_ipam_scan.php:']           = array('title' => __('Network Scan', 'cereus_ipam'),       'mapping' => 'index.php:', 'url' => 'cereus_ipam_scan.php',           'level' => '1');
	$nav['cereus_ipam_import.php:']         = array('title' => __('CSV Import', 'cereus_ipam'),         'mapping' => 'index.php:,cereus_ipam.php:', 'url' => 'cereus_ipam_import.php', 'level' => '2');
	$nav['cereus_ipam_maintenance.php:']    = array('title' => __('Maintenance Windows', 'cereus_ipam'), 'mapping' => 'index.php:', 'url' => 'cereus_ipam_maintenance.php', 'level' => '1');
	$nav['cereus_ipam_maintenance.php:edit'] = array('title' => __('(Edit)', 'cereus_ipam'),            'mapping' => 'index.php:,cereus_ipam_maintenance.php:', 'url' => '', 'level' => '2');
	$nav['cereus_ipam_dhcp.php:']           = array('title' => __('DHCP Scopes', 'cereus_ipam'),        'mapping' => 'index.php:', 'url' => 'cereus_ipam_dhcp.php', 'level' => '1');
	$nav['cereus_ipam_dhcp.php:edit']       = array('title' => __('(Edit)', 'cereus_ipam'),            'mapping' => 'index.php:,cereus_ipam_dhcp.php:', 'url' => '', 'level' => '2');
	$nav['cereus_ipam_calculator.php:']     = array('title' => __('Subnet Calculator', 'cereus_ipam'),  'mapping' => 'index.php:', 'url' => 'cereus_ipam_calculator.php', 'level' => '1');
	$nav['cereus_ipam_tenants.php:']       = array('title' => __('Tenants', 'cereus_ipam'),             'mapping' => 'index.php:', 'url' => 'cereus_ipam_tenants.php', 'level' => '1');
	$nav['cereus_ipam_tenants.php:edit']   = array('title' => __('(Edit)', 'cereus_ipam'),              'mapping' => 'index.php:,cereus_ipam_tenants.php:', 'url' => '', 'level' => '2');
	$nav['cereus_ipam_locations.php:']     = array('title' => __('Locations', 'cereus_ipam'),  'mapping' => 'index.php:', 'url' => 'cereus_ipam_locations.php', 'level' => '1');
	$nav['cereus_ipam_locations.php:edit'] = array('title' => __('(Edit)', 'cereus_ipam'),     'mapping' => 'index.php:,cereus_ipam_locations.php:', 'url' => '', 'level' => '2');
	$nav['cereus_ipam_addresses.php:fill_range'] = array('title' => __('Fill Range', 'cereus_ipam'),    'mapping' => 'index.php:,cereus_ipam.php:,cereus_ipam_addresses.php:', 'url' => '', 'level' => '3');
	$nav['cereus_ipam_addresses.php:history']    = array('title' => __('Address History', 'cereus_ipam'), 'mapping' => 'index.php:,cereus_ipam.php:,cereus_ipam_addresses.php:', 'url' => '', 'level' => '3');
	$nav['cereus_ipam_addresses.php:visual']     = array('title' => __('Visual Map', 'cereus_ipam'),      'mapping' => 'index.php:,cereus_ipam.php:,cereus_ipam_addresses.php:', 'url' => '', 'level' => '3');
	$nav['cereus_ipam_search.php:']              = array('title' => __('IPAM Search', 'cereus_ipam'),     'mapping' => 'index.php:', 'url' => 'cereus_ipam_search.php', 'level' => '1');
	$nav['cereus_ipam_tags.php:']                = array('title' => __('IPAM Tags', 'cereus_ipam'),       'mapping' => 'index.php:', 'url' => 'cereus_ipam_tags.php', 'level' => '1');
	$nav['cereus_ipam_tags.php:edit']            = array('title' => __('(Edit)', 'cereus_ipam'),          'mapping' => 'index.php:,cereus_ipam_tags.php:', 'url' => '', 'level' => '2');
	return $nav;
}

/* ==================== Page Head Hook ==================== */

/**
 * Inject webhook test button JS on the IPAM settings tab.
 * Hook: page_head
 */
function cereus_ipam_settings_bottom() {
	/* Only inject on our settings tab */
	$tab = get_nfilter_request_var('tab', '');
	if ($tab !== 'cereus_ipam') {
		return;
	}

	?>
	<script type='text/javascript'>
	$(function() {
		/* Default-collapse feature sections on first visit */
		var storage = Storages.localStorage;
		var collapseSections = [
			'row_cereus_ipam_scan_header',
			'row_cereus_ipam_threshold_header',
			'row_cereus_ipam_report_header',
			'row_cereus_ipam_webhook_header'
		];

		$.each(collapseSections, function(i, id) {
			var key = id + '_cs';
			if (!storage.isSet(key)) {
				storage.set(key, 'hide');
				$('#' + id).addClass('collapsed');
				$('#' + id).nextUntil('div.spacer').hide();
				$('#' + id).find('i').removeClass('fa-angle-double-up').addClass('fa-angle-double-down');
			}
		});

		var $urlInput = $('#cereus_ipam_webhook_test_url');
		if ($urlInput.length) {
			var $btn = $('<input type="button" class="ui-button ui-corner-all ui-widget" value="<?php print __esc('Test Webhook', 'cereus_ipam'); ?>" style="margin-left:5px;">');
			var $result = $('<span style="margin-left:8px;"></span>');
			$urlInput.after($result).after($btn);

			$btn.click(function() {
				var u = $urlInput.val();
				if (!u) {
					$result.html('<span style="color:red;"><?php print __esc('Enter a URL first', 'cereus_ipam'); ?></span>');
					return;
				}
				$result.text('<?php print __esc('Testing...', 'cereus_ipam'); ?>');
				$.getJSON('plugins/cereus_ipam/cereus_ipam_webhook_test.php?url=' + encodeURIComponent(u), function(d) {
					if (d.success) {
						$result.html('<span style="color:green;">Success (HTTP ' + d.http_code + ')</span>');
					} else {
						$result.html('<span style="color:red;">Failed: ' + (d.error || 'HTTP ' + d.http_code) + '</span>');
					}
				}).fail(function() {
					$result.html('<span style="color:red;"><?php print __esc('Request failed', 'cereus_ipam'); ?></span>');
				});
			});
		}
	});
	</script>
	<?php
}

/* ==================== Poller Hook ==================== */

function cereus_ipam_poller_bottom() {
	global $config;

	/* Only run on primary poller */
	if (isset($config['poller_id']) && $config['poller_id'] > 1) {
		return;
	}

	include_once(__DIR__ . '/includes/constants.php');
	include_once(__DIR__ . '/lib/license_check.php');
	include_once(__DIR__ . '/lib/validation.php');
	include_once(__DIR__ . '/lib/ip_utils.php');
	include_once(__DIR__ . '/lib/functions.php');
	include_once(__DIR__ . '/lib/changelog.php');

	$enabled = read_config_option('cereus_ipam_enabled');
	if ($enabled != 'on') {
		return;
	}

	$start = microtime(true);

	/* Device sync */
	if (read_config_option('cereus_ipam_device_sync') == 'on') {
		cereus_ipam_device_sync();
	}

	/* Scheduled scans (Professional+) */
	if (cereus_ipam_license_has_scanning()) {
		include_once(__DIR__ . '/lib/scanner.php');
		cereus_ipam_run_scheduled_scans();
	}

	/* DHCP scope polling (Enterprise) */
	if (cereus_ipam_license_has_dhcp_monitoring()) {
		include_once(__DIR__ . '/lib/dhcp.php');
		cereus_ipam_dhcp_poll_all();
	}

	/* Check threshold alerts */
	include_once($config['base_path'] . '/plugins/cereus_ipam/lib/threshold.php');
	cereus_ipam_check_thresholds();

	/* Record utilization history for capacity forecasting */
	if (cereus_ipam_license_at_least('enterprise')) {
		include_once($config['base_path'] . '/plugins/cereus_ipam/lib/forecast.php');
		cereus_ipam_record_utilization();
	}

	/* Automated reconciliation (Enterprise) */
	if (cereus_ipam_license_has_reconciliation()) {
		include_once($config['base_path'] . '/plugins/cereus_ipam/lib/reconciliation.php');
		cereus_ipam_reconcile_all();
	}

	/* Scheduled report emails (Professional+) */
	if (cereus_ipam_license_at_least('professional')) {
		include_once($config['base_path'] . '/plugins/cereus_ipam/lib/report_scheduler.php');
		cereus_ipam_check_scheduled_reports();
	}

	/* Changelog purge */
	$retention = cereus_ipam_license_log_retention();
	if ($retention > 0) {
		cereus_ipam_changelog_purge($retention);
	}

	/* Scan results purge (keep 30 days) */
	db_execute("DELETE FROM plugin_cereus_ipam_scan_results WHERE scanned_at < DATE_SUB(NOW(), INTERVAL 30 DAY)");

	/* Utilization history purge (keep 365 days) */
	db_execute("DELETE FROM plugin_cereus_ipam_utilization_history WHERE recorded_at < DATE_SUB(NOW(), INTERVAL 365 DAY)");

	$end = microtime(true);
	$runtime = round(($end - $start) * 1000);

	set_config_option('cereus_ipam_stats', "time:$runtime");
}

/* ==================== Device Page Hooks ==================== */

/**
 * Show IPAM address info on the device edit page (host.php?action=edit).
 * Hook: device_edit_pre_bottom
 */
function cereus_ipam_device_edit_pre_bottom() {
	global $config;

	$host_id = get_filter_request_var('id');
	if (empty($host_id)) {
		return;
	}

	$addresses = db_fetch_assoc_prepared(
		"SELECT a.ip, a.hostname, a.state, a.subnet_id, a.description,
			CONCAT(s.subnet, '/', s.mask) AS cidr
		FROM plugin_cereus_ipam_addresses a
		LEFT JOIN plugin_cereus_ipam_subnets s ON s.id = a.subnet_id
		WHERE a.cacti_host_id = ?
		ORDER BY a.ip",
		array($host_id)
	);

	if (!cacti_sizeof($addresses)) {
		return;
	}

	$plugin_url = $config['url_path'] . 'plugins/cereus_ipam/';

	html_start_box(__('IPAM Addresses', 'cereus_ipam'), '100%', '', '3', 'center', '');

	$display_text = array(
		array('display' => __('IP Address', 'cereus_ipam'), 'align' => 'left'),
		array('display' => __('Subnet', 'cereus_ipam'),     'align' => 'left'),
		array('display' => __('Hostname', 'cereus_ipam'),   'align' => 'left'),
		array('display' => __('State', 'cereus_ipam'),      'align' => 'left'),
		array('display' => __('Description', 'cereus_ipam'), 'align' => 'left'),
	);
	html_header($display_text);

	foreach ($addresses as $row) {
		form_alternate_row();
		print '<td><a class="linkEditMain" href="' . html_escape($plugin_url . 'cereus_ipam_addresses.php?subnet_id=' . $row['subnet_id']) . '">'
			. html_escape($row['ip']) . '</a></td>';
		print '<td><a href="' . html_escape($plugin_url . 'cereus_ipam.php?action=edit&id=' . $row['subnet_id']) . '">'
			. html_escape($row['cidr'] ?? '') . '</a></td>';
		print '<td>' . html_escape($row['hostname'] ?? '') . '</td>';
		print '<td>' . html_escape(ucfirst($row['state'])) . '</td>';
		print '<td>' . html_escape($row['description'] ?? '') . '</td>';
		form_end_row();
	}

	html_end_box();
}

/**
 * Add "IPAM Subnet" column to the device list table.
 * Hook: device_display_text (function hook — receives and returns $display_text)
 */
function cereus_ipam_device_display_text($display_text) {
	$display_text[] = array('display' => __('IPAM Subnet', 'cereus_ipam'), 'align' => 'left', 'tip' => __('IPAM subnet for this device', 'cereus_ipam'));
	return $display_text;
}

/**
 * Render the extra IPAM column for each device in the device list.
 * Hook: device_table_replace (function hook — receives $hosts array)
 */
function cereus_ipam_device_table_replace($hosts) {
	global $config;

	if (!cacti_sizeof($hosts)) {
		return $hosts;
	}

	/* Pre-fetch all IPAM mappings for displayed host IDs */
	$host_ids = array();
	foreach ($hosts as $host) {
		if (isset($host['id'])) {
			$host_ids[] = $host['id'];
		}
	}

	$ipam_map = array();
	if (cacti_sizeof($host_ids)) {
		$placeholders = implode(',', array_fill(0, count($host_ids), '?'));
		$rows = db_fetch_assoc_prepared(
			"SELECT a.cacti_host_id, a.ip, a.subnet_id,
				CONCAT(s.subnet, '/', s.mask) AS cidr
			FROM plugin_cereus_ipam_addresses a
			LEFT JOIN plugin_cereus_ipam_subnets s ON s.id = a.subnet_id
			WHERE a.cacti_host_id IN ($placeholders)
			ORDER BY a.cacti_host_id, a.ip",
			$host_ids
		);

		foreach ($rows as $r) {
			if (!isset($ipam_map[$r['cacti_host_id']])) {
				$ipam_map[$r['cacti_host_id']] = $r;
			}
		}
	}

	$plugin_url = $config['url_path'] . 'plugins/cereus_ipam/';

	foreach ($hosts as &$host) {
		$hid = $host['id'] ?? 0;
		if (isset($ipam_map[$hid])) {
			$m = $ipam_map[$hid];
			$host['cereus_ipam'] = '<a href="' . html_escape($plugin_url . 'cereus_ipam_addresses.php?subnet_id=' . $m['subnet_id']) . '">'
				. html_escape($m['cidr']) . '</a>';
		} else {
			$host['cereus_ipam'] = '';
		}
	}

	return $hosts;
}
