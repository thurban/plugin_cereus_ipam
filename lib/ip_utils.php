<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2024-2026 Urban-Software.de / Thomas Urban               |
 +-------------------------------------------------------------------------+
 | Cereus IPAM - IPv4/IPv6 Calculation Library                             |
 | Replaces deprecated PEAR Net_IPv4 with pure-PHP + GMP implementation   |
 +-------------------------------------------------------------------------+
*/

/**
 * Determine IP version (4 or 6).
 */
function cereus_ipam_ip_version($ip) {
	if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
		return 4;
	}
	if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
		return 6;
	}
	return false;
}

/**
 * Convert IP address to binary string for comparison/sorting.
 * Returns a 4-byte (IPv4) or 16-byte (IPv6) binary string.
 */
function cereus_ipam_ip_to_binary($ip) {
	return inet_pton($ip);
}

/**
 * Convert binary string back to IP address.
 */
function cereus_ipam_binary_to_ip($binary) {
	return inet_ntop($binary);
}

/**
 * Convert IP to GMP number for arithmetic.
 */
function cereus_ipam_ip_to_gmp($ip) {
	$binary = inet_pton($ip);
	if ($binary === false) {
		return false;
	}
	$hex = bin2hex($binary);
	return gmp_init($hex, 16);
}

/**
 * Convert GMP number back to IP address.
 */
function cereus_ipam_gmp_to_ip($gmp, $version = 4) {
	$hex = gmp_strval($gmp, 16);
	$length = ($version == 6) ? 32 : 8;
	$hex = str_pad($hex, $length, '0', STR_PAD_LEFT);
	$binary = hex2bin($hex);
	return inet_ntop($binary);
}

/**
 * Calculate the network address for a given IP and CIDR mask.
 */
function cereus_ipam_network_address($ip, $mask) {
	$version = cereus_ipam_ip_version($ip);
	$bits = ($version == 6) ? 128 : 32;

	$ip_gmp   = cereus_ipam_ip_to_gmp($ip);
	$mask_gmp = cereus_ipam_cidr_to_mask_gmp($mask, $bits);

	$network = gmp_and($ip_gmp, $mask_gmp);
	return cereus_ipam_gmp_to_ip($network, $version);
}

/**
 * Calculate the broadcast address for a given subnet.
 */
function cereus_ipam_broadcast_address($subnet, $mask) {
	$version = cereus_ipam_ip_version($subnet);
	$bits = ($version == 6) ? 128 : 32;

	$network_gmp = cereus_ipam_ip_to_gmp($subnet);
	$mask_gmp    = cereus_ipam_cidr_to_mask_gmp($mask, $bits);
	$wildcard    = gmp_xor($mask_gmp, gmp_sub(gmp_pow(2, $bits), 1));
	$broadcast   = gmp_or($network_gmp, $wildcard);

	return cereus_ipam_gmp_to_ip($broadcast, $version);
}

/**
 * Convert CIDR prefix length to GMP netmask.
 */
function cereus_ipam_cidr_to_mask_gmp($mask, $bits = 32) {
	if ($mask == 0) {
		return gmp_init(0);
	}
	$all_ones = gmp_sub(gmp_pow(2, $bits), 1);
	$host_bits = $bits - $mask;
	$shift = gmp_pow(2, $host_bits);
	$mask_val = gmp_sub($all_ones, gmp_sub($shift, 1));
	return $mask_val;
}

/**
 * Get first and last IP of a subnet.
 * Returns array('first' => ip, 'last' => ip).
 */
function cereus_ipam_cidr_to_range($subnet, $mask) {
	$version = cereus_ipam_ip_version($subnet);
	$bits = ($version == 6) ? 128 : 32;

	$network_gmp = cereus_ipam_ip_to_gmp($subnet);
	$mask_gmp    = cereus_ipam_cidr_to_mask_gmp($mask, $bits);
	$wildcard    = gmp_xor($mask_gmp, gmp_sub(gmp_pow(2, $bits), 1));

	$first = gmp_and($network_gmp, $mask_gmp);
	$last  = gmp_or($first, $wildcard);

	return array(
		'first' => cereus_ipam_gmp_to_ip($first, $version),
		'last'  => cereus_ipam_gmp_to_ip($last, $version),
	);
}

/**
 * Check if an IP is within a subnet.
 */
function cereus_ipam_ip_in_subnet($ip, $subnet, $mask) {
	$ip_version = cereus_ipam_ip_version($ip);
	$subnet_version = cereus_ipam_ip_version($subnet);

	if ($ip_version !== $subnet_version) {
		return false;
	}

	$bits = ($ip_version == 6) ? 128 : 32;
	$mask_gmp = cereus_ipam_cidr_to_mask_gmp($mask, $bits);

	$ip_network     = gmp_and(cereus_ipam_ip_to_gmp($ip), $mask_gmp);
	$subnet_network = gmp_and(cereus_ipam_ip_to_gmp($subnet), $mask_gmp);

	return gmp_cmp($ip_network, $subnet_network) === 0;
}

/**
 * Calculate the total number of addresses in a subnet.
 */
function cereus_ipam_subnet_size($mask, $version = 4) {
	$bits = ($version == 6) ? 128 : 32;
	$host_bits = $bits - $mask;
	return gmp_strval(gmp_pow(2, $host_bits));
}

/**
 * Calculate the number of usable host addresses.
 * For IPv4 /31 and /32: special cases. For IPv6: all addresses usable.
 */
function cereus_ipam_usable_hosts($mask, $version = 4) {
	if ($version == 4) {
		if ($mask == 32) return '1';
		if ($mask == 31) return '2';
		$total = gmp_pow(2, 32 - $mask);
		return gmp_strval(gmp_sub($total, 2));
	}
	return cereus_ipam_subnet_size($mask, 6);
}

/**
 * Find the next available IP in a subnet.
 * Returns the IP string or false if subnet is full.
 */
function cereus_ipam_next_available($subnet_id) {
	$subnet = db_fetch_row_prepared("SELECT subnet, mask FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
	if (!cacti_sizeof($subnet)) {
		return false;
	}

	$version = cereus_ipam_ip_version($subnet['subnet']);
	$range = cereus_ipam_cidr_to_range($subnet['subnet'], $subnet['mask']);

	$start_gmp = cereus_ipam_ip_to_gmp($range['first']);
	$end_gmp   = cereus_ipam_ip_to_gmp($range['last']);

	/* For IPv4, skip network and broadcast addresses (except /31 and /32) */
	if ($version == 4 && $subnet['mask'] < 31) {
		$start_gmp = gmp_add($start_gmp, 1);
		$end_gmp   = gmp_sub($end_gmp, 1);
	}

	/* Get all used IPs in this subnet */
	$used_ips = db_fetch_assoc_prepared("SELECT ip FROM plugin_cereus_ipam_addresses WHERE subnet_id = ?", array($subnet_id));
	$used_set = array();
	if (cacti_sizeof($used_ips)) {
		foreach ($used_ips as $row) {
			$used_set[$row['ip']] = true;
		}
	}

	/* Scan for first free IP */
	$current = $start_gmp;
	while (gmp_cmp($current, $end_gmp) <= 0) {
		$ip = cereus_ipam_gmp_to_ip($current, $version);
		if (!isset($used_set[$ip])) {
			return $ip;
		}
		$current = gmp_add($current, 1);
	}

	return false;
}

/**
 * Calculate subnet utilization statistics.
 * Returns array('used', 'free', 'total', 'pct').
 */
function cereus_ipam_subnet_utilization($subnet_id) {
	$subnet = db_fetch_row_prepared("SELECT subnet, mask FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));
	if (!cacti_sizeof($subnet)) {
		return array('used' => 0, 'free' => 0, 'total' => 0, 'pct' => 0);
	}

	$version = cereus_ipam_ip_version($subnet['subnet']);
	$total = cereus_ipam_usable_hosts($subnet['mask'], $version);
	$used = (int) db_fetch_cell_prepared("SELECT COUNT(*) FROM plugin_cereus_ipam_addresses WHERE subnet_id = ?", array($subnet_id));

	$total_int = intval($total);
	if ($total_int > 0) {
		$free = $total_int - $used;
		$pct  = round(($used / $total_int) * 100, 1);
	} else {
		$free = 0;
		$pct  = 0;
	}

	return array(
		'used'  => $used,
		'free'  => max(0, $free),
		'total' => $total_int,
		'pct'   => $pct,
	);
}

/**
 * Format a subnet for display: "10.0.0.0/24"
 */
function cereus_ipam_format_subnet($subnet, $mask) {
	return $subnet . '/' . $mask;
}

/**
 * Compare two IPs for sorting. Returns -1, 0, or 1.
 */
function cereus_ipam_ip_compare($ip_a, $ip_b) {
	$a = cereus_ipam_ip_to_binary($ip_a);
	$b = cereus_ipam_ip_to_binary($ip_b);
	return strcmp($a, $b);
}

/**
 * Get the subnet mask in dotted-decimal notation (IPv4 only).
 */
function cereus_ipam_cidr_to_dotted($mask) {
	$mask = (int) $mask;
	if ($mask < 0 || $mask > 32) {
		return false;
	}
	$bin = str_repeat('1', $mask) . str_repeat('0', 32 - $mask);
	return long2ip(bindec($bin));
}
