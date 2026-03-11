<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2024-2026 Urban-Software.de / Thomas Urban               |
 +-------------------------------------------------------------------------+
 | Cereus IPAM - Input Validation                                          |
 +-------------------------------------------------------------------------+
*/

/**
 * Validate an IP address (IPv4 or IPv6).
 */
function cereus_ipam_validate_ip($ip) {
	return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

/**
 * Validate an IPv4 address specifically.
 */
function cereus_ipam_validate_ipv4($ip) {
	return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
}

/**
 * Validate an IPv6 address specifically.
 */
function cereus_ipam_validate_ipv6($ip) {
	return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
}

/**
 * Validate a CIDR prefix length.
 * IPv4: 0-32, IPv6: 0-128
 */
function cereus_ipam_validate_cidr($mask, $version = 4) {
	$mask = (int) $mask;
	if ($version == 6) {
		return ($mask >= 0 && $mask <= 128);
	}
	return ($mask >= 0 && $mask <= 32);
}

/**
 * Validate a MAC address in XX:XX:XX:XX:XX:XX format.
 */
function cereus_ipam_validate_mac($mac) {
	return (bool) preg_match('/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/', $mac);
}

/**
 * Normalize a MAC address to uppercase colon-separated format.
 */
function cereus_ipam_normalize_mac($mac) {
	$mac = strtoupper(trim($mac));
	$mac = preg_replace('/[^0-9A-F]/', '', $mac);
	if (strlen($mac) !== 12) {
		return false;
	}
	return implode(':', str_split($mac, 2));
}

/**
 * Validate that a subnet address matches its mask (is a proper network address).
 */
function cereus_ipam_validate_subnet($addr, $mask) {
	if (!cereus_ipam_validate_ip($addr)) {
		return false;
	}

	$version = cereus_ipam_ip_version($addr);
	if (!cereus_ipam_validate_cidr($mask, $version)) {
		return false;
	}

	$network = cereus_ipam_network_address($addr, $mask);
	return ($network === $addr);
}

/**
 * Validate a VLAN number (1-4094).
 */
function cereus_ipam_validate_vlan($num) {
	$num = (int) $num;
	return ($num >= 1 && $num <= 4094);
}

/**
 * Validate a hostname per RFC 1123.
 */
function cereus_ipam_validate_hostname($name) {
	if (strlen($name) > 253) {
		return false;
	}
	return (bool) preg_match('/^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$/', $name);
}

/**
 * Sanitize text input: strip tags, limit length.
 */
function cereus_ipam_sanitize_text($text, $max_length = 255) {
	$text = strip_tags(trim($text));
	if (strlen($text) > $max_length) {
		$text = substr($text, 0, $max_length);
	}
	return $text;
}

/**
 * Validate a CIDR notation string (e.g., "192.168.1.0/24").
 * Returns array('subnet' => ..., 'mask' => ...) or false.
 */
function cereus_ipam_parse_cidr($cidr) {
	$parts = explode('/', $cidr, 2);
	if (count($parts) !== 2) {
		return false;
	}

	$subnet = trim($parts[0]);
	$mask   = (int) trim($parts[1]);

	if (!cereus_ipam_validate_ip($subnet)) {
		return false;
	}

	$version = cereus_ipam_ip_version($subnet);
	if (!cereus_ipam_validate_cidr($mask, $version)) {
		return false;
	}

	return array('subnet' => $subnet, 'mask' => $mask);
}

/**
 * Validate a state value against allowed states.
 */
function cereus_ipam_validate_state($state) {
	$allowed = array('active', 'reserved', 'dhcp', 'offline', 'available');
	return in_array($state, $allowed, true);
}
