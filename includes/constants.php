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
 | Cereus IPAM - Constants                                                 |
 +-------------------------------------------------------------------------+
*/

/* Address States */
define('CEREUS_IPAM_STATE_ACTIVE',    'active');
define('CEREUS_IPAM_STATE_RESERVED',  'reserved');
define('CEREUS_IPAM_STATE_DHCP',      'dhcp');
define('CEREUS_IPAM_STATE_OFFLINE',   'offline');
define('CEREUS_IPAM_STATE_AVAILABLE', 'available');

/* Scan Types */
define('CEREUS_IPAM_SCAN_PING', 'ping');
define('CEREUS_IPAM_SCAN_ARP',  'arp');
define('CEREUS_IPAM_SCAN_SNMP', 'snmp');
define('CEREUS_IPAM_SCAN_DNS',  'dns');

/* Changelog Actions */
define('CEREUS_IPAM_ACTION_CREATE',   'create');
define('CEREUS_IPAM_ACTION_UPDATE',   'update');
define('CEREUS_IPAM_ACTION_DELETE',   'delete');
define('CEREUS_IPAM_ACTION_IMPORT',   'import');
define('CEREUS_IPAM_ACTION_SCAN',     'scan');
define('CEREUS_IPAM_ACTION_TRUNCATE', 'truncate');

/* Changelog Object Types */
define('CEREUS_IPAM_OBJ_SECTION',      'section');
define('CEREUS_IPAM_OBJ_SUBNET',       'subnet');
define('CEREUS_IPAM_OBJ_ADDRESS',      'address');
define('CEREUS_IPAM_OBJ_VLAN',         'vlan');
define('CEREUS_IPAM_OBJ_VRF',          'vrf');
define('CEREUS_IPAM_OBJ_CUSTOM_FIELD', 'custom_field');
define('CEREUS_IPAM_OBJ_SETTING',      'setting');

/* Custom Field Types */
define('CEREUS_IPAM_CF_TEXT',     'text');
define('CEREUS_IPAM_CF_TEXTAREA', 'textarea');
define('CEREUS_IPAM_CF_DROPDOWN', 'dropdown');
define('CEREUS_IPAM_CF_CHECKBOX', 'checkbox');
define('CEREUS_IPAM_CF_DATE',     'date');
define('CEREUS_IPAM_CF_URL',      'url');

/* Community Tier Limits */
define('CEREUS_IPAM_COMMUNITY_MAX_SUBNETS',     10);
define('CEREUS_IPAM_COMMUNITY_MAX_IMPORT_ROWS',  500);
define('CEREUS_IPAM_COMMUNITY_LOG_RETENTION',     30);

/* Global dropdown arrays */
global $cereus_ipam_states, $cereus_ipam_scan_types, $cereus_ipam_cf_types;

$cereus_ipam_states = array(
	CEREUS_IPAM_STATE_ACTIVE    => __('Active', 'cereus_ipam'),
	CEREUS_IPAM_STATE_RESERVED  => __('Reserved', 'cereus_ipam'),
	CEREUS_IPAM_STATE_DHCP      => __('DHCP', 'cereus_ipam'),
	CEREUS_IPAM_STATE_OFFLINE   => __('Offline', 'cereus_ipam'),
	CEREUS_IPAM_STATE_AVAILABLE => __('Available', 'cereus_ipam'),
);

$cereus_ipam_scan_types = array(
	CEREUS_IPAM_SCAN_PING => __('Ping Sweep', 'cereus_ipam'),
	CEREUS_IPAM_SCAN_ARP  => __('ARP Table (SNMP)', 'cereus_ipam'),
	CEREUS_IPAM_SCAN_SNMP => __('SNMP Discovery', 'cereus_ipam'),
	CEREUS_IPAM_SCAN_DNS  => __('DNS Lookup', 'cereus_ipam'),
);

$cereus_ipam_cf_types = array(
	CEREUS_IPAM_CF_TEXT     => __('Text', 'cereus_ipam'),
	CEREUS_IPAM_CF_TEXTAREA => __('Textarea', 'cereus_ipam'),
	CEREUS_IPAM_CF_DROPDOWN => __('Dropdown', 'cereus_ipam'),
	CEREUS_IPAM_CF_CHECKBOX => __('Checkbox', 'cereus_ipam'),
	CEREUS_IPAM_CF_DATE     => __('Date', 'cereus_ipam'),
	CEREUS_IPAM_CF_URL      => __('URL', 'cereus_ipam'),
);
