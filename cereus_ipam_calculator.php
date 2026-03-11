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
 | Cereus IPAM - Subnet Calculator                                         |
 +-------------------------------------------------------------------------+
*/

chdir('../../');
include('./include/auth.php');
include_once('./plugins/cereus_ipam/includes/constants.php');
include_once('./plugins/cereus_ipam/lib/license_check.php');
include_once('./plugins/cereus_ipam/lib/validation.php');
include_once('./plugins/cereus_ipam/lib/ip_utils.php');
include_once('./plugins/cereus_ipam/lib/functions.php');

top_header();
cereus_ipam_calculator_page();
bottom_footer();

/* ==================== Calculator Page ==================== */

function cereus_ipam_calculator_page() {
	$ip   = get_nfilter_request_var('ip', '');
	$mask = get_filter_request_var('mask', FILTER_VALIDATE_INT);
	$calc = get_nfilter_request_var('calculate', '');

	if ($mask === false || $mask === null) {
		$mask = 24;
	}

	/* Build CIDR dropdown options /1 through /128 */
	$cidr_options = array();
	for ($i = 1; $i <= 128; $i++) {
		$cidr_options[$i] = '/' . $i;
	}

	/* Input form */
	$fields = array(
		'calc_header' => array(
			'friendly_name' => __('Subnet Calculator', 'cereus_ipam'),
			'method'        => 'spacer',
		),
		'ip' => array(
			'friendly_name' => __('IP Address', 'cereus_ipam'),
			'description'   => __('Enter an IPv4 or IPv6 address (e.g. 192.168.1.0 or 2001:db8::1).', 'cereus_ipam'),
			'method'        => 'textbox',
			'value'         => html_escape($ip),
			'max_length'    => 45,
			'size'          => 40,
		),
		'mask' => array(
			'friendly_name' => __('CIDR Mask', 'cereus_ipam'),
			'description'   => __('Select the prefix length (CIDR notation).', 'cereus_ipam'),
			'method'        => 'drop_array',
			'value'         => $mask,
			'default'       => 24,
			'array'         => $cidr_options,
		),
	);

	form_start('cereus_ipam_calculator.php', 'cipam_calc');
	html_start_box(__('Subnet Calculator', 'cereus_ipam'), '100%', '', '3', 'center', '');
	draw_edit_form(array(
		'config' => array('no_form_tag' => true),
		'fields' => $fields,
	));

	/* Calculate button row */
	print '<tr><td colspan="2" class="saveRow">';
	print '<input type="hidden" name="calculate" value="1">';
	print '<input type="submit" class="ui-button ui-corner-all ui-widget" value="' . __esc('Calculate', 'cereus_ipam') . '">';
	print '</td></tr>';

	html_end_box();
	form_end();

	/* Process calculation if submitted */
	if ($calc == '1' && !empty($ip)) {
		cereus_ipam_calculator_results($ip, $mask);
	}
}

/* ==================== Results Display ==================== */

function cereus_ipam_calculator_results($ip, $mask) {
	$ip = trim($ip);

	/* Validate IP */
	if (!cereus_ipam_validate_ip($ip)) {
		html_start_box(__('Error', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr class="even"><td style="padding:8px 15px;"><em>' . __('Invalid IP address. Please enter a valid IPv4 or IPv6 address.', 'cereus_ipam') . '</em></td></tr>';
		html_end_box();
		return;
	}

	$version = cereus_ipam_ip_version($ip);

	/* Validate CIDR mask range for the IP version */
	$max_mask = ($version == 6) ? 128 : 32;
	$mask = (int) $mask;

	if ($mask < 1 || $mask > $max_mask) {
		html_start_box(__('Error', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr class="even"><td style="padding:8px 15px;"><em>';
		print __('Invalid CIDR mask for IPv%d. Allowed range: /1 to /%d.', $version, $max_mask, 'cereus_ipam');
		print '</em></td></tr>';
		html_end_box();
		return;
	}

	/* Calculate all values */
	$network   = cereus_ipam_network_address($ip, $mask);
	$broadcast = ($version == 4) ? cereus_ipam_broadcast_address($network, $mask) : '';
	$range     = cereus_ipam_cidr_to_range($network, $mask);
	$total     = cereus_ipam_subnet_size($mask, $version);
	$usable    = cereus_ipam_usable_hosts($mask, $version);

	/* First/last usable host */
	if ($version == 4) {
		if ($mask == 32) {
			$first_host = $network;
			$last_host  = $network;
		} elseif ($mask == 31) {
			$first_host = $range['first'];
			$last_host  = $range['last'];
		} else {
			/* First usable = network + 1, last usable = broadcast - 1 */
			$first_gmp = gmp_add(cereus_ipam_ip_to_gmp($range['first']), 1);
			$last_gmp  = gmp_sub(cereus_ipam_ip_to_gmp($range['last']), 1);
			$first_host = cereus_ipam_gmp_to_ip($first_gmp, 4);
			$last_host  = cereus_ipam_gmp_to_ip($last_gmp, 4);
		}
	} else {
		/* IPv6: all addresses are usable */
		$first_host = $range['first'];
		$last_host  = $range['last'];
	}

	/* Subnet mask in dotted decimal (IPv4 only) */
	$dotted_mask = ($version == 4) ? cereus_ipam_cidr_to_dotted($mask) : '';

	/* Wildcard mask (IPv4 only) - invert the dotted mask */
	$wildcard = '';
	if ($version == 4 && $dotted_mask !== false) {
		$parts = explode('.', $dotted_mask);
		$inverted = array();
		foreach ($parts as $octet) {
			$inverted[] = 255 - (int) $octet;
		}
		$wildcard = implode('.', $inverted);
	}

	/* CIDR notation */
	$cidr_notation = $network . '/' . $mask;

	/* Display results */
	html_start_box(__('Calculation Results for %s/%s', html_escape($ip), $mask, 'cereus_ipam'), '100%', '', '3', 'center', '');

	$results = array(
		array(__('IP Version', 'cereus_ipam'),       __('IPv%d', $version, 'cereus_ipam')),
		array(__('Network Address', 'cereus_ipam'),   html_escape($network)),
	);

	if ($version == 4) {
		$results[] = array(__('Broadcast Address', 'cereus_ipam'), html_escape($broadcast));
	}

	$results[] = array(__('First Usable Host', 'cereus_ipam'), html_escape($first_host));
	$results[] = array(__('Last Usable Host', 'cereus_ipam'),  html_escape($last_host));
	$results[] = array(__('Total Addresses', 'cereus_ipam'),   html_escape($total));
	$results[] = array(__('Usable Hosts', 'cereus_ipam'),      html_escape($usable));

	if ($version == 4) {
		$results[] = array(__('Subnet Mask', 'cereus_ipam'),   html_escape($dotted_mask));
		$results[] = array(__('Wildcard Mask', 'cereus_ipam'), html_escape($wildcard));
	}

	$results[] = array(__('CIDR Notation', 'cereus_ipam'), html_escape($cidr_notation));

	$i = 0;
	foreach ($results as $row) {
		$class = ($i % 2 == 0) ? 'even' : 'odd';
		print '<tr class="' . $class . '">';
		print '<td style="padding:4px 15px; width:200px;"><strong>' . $row[0] . '</strong></td>';
		print '<td style="padding:4px 15px;">' . $row[1] . '</td>';
		print '</tr>';
		$i++;
	}

	html_end_box();
}
