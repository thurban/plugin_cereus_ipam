<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2024-2026 Urban-Software.de / Thomas Urban               |
 +-------------------------------------------------------------------------+
 | Cereus IPAM - Network Scanner (Professional+)                           |
 +-------------------------------------------------------------------------+
*/

/**
 * Get the effective scan method for the current execution context.
 *
 * @return string 'fping' or 'tcp'
 */
function cereus_ipam_scan_get_method() {
	$configured = read_config_option('cereus_ipam_scan_method');

	if ($configured === 'fping') {
		return 'fping';
	}

	if ($configured === 'tcp') {
		return 'tcp';
	}

	/* auto: fping from CLI/poller (runs as root, no SELinux httpd_t),
	 * TCP parallel from web (always works, no raw sockets needed) */
	if (php_sapi_name() === 'cli') {
		$fping_path = cereus_ipam_scan_find_fping();
		if (!empty($fping_path)) {
			return 'fping';
		}
	}

	return 'tcp';
}

/**
 * Locate the fping binary.
 *
 * @return string path or empty string
 */
function cereus_ipam_scan_find_fping() {
	global $config;

	$configured = read_config_option('cereus_ipam_fping_path');

	if (!empty($configured) && is_executable($configured)) {
		return $configured;
	}

	/* Auto-detect based on platform */
	if ($config['cacti_server_os'] == 'win32') {
		/* Windows: check common locations and Cacti's configured path */
		$cacti_fping = read_config_option('path_fping');

		if (!empty($cacti_fping) && is_executable($cacti_fping)) {
			return $cacti_fping;
		}

		$candidates = array(
			'C:\\fping\\fping.exe',
			$config['base_path'] . '\\fping.exe',
		);

		/* Also check PATH */
		$path_dirs = explode(';', getenv('PATH'));

		foreach ($path_dirs as $dir) {
			$dir = rtrim($dir, '\\');

			if (!empty($dir)) {
				$candidates[] = $dir . '\\fping.exe';
			}
		}
	} else {
		$candidates = array('/usr/sbin/fping', '/usr/bin/fping', '/usr/local/sbin/fping', '/usr/local/bin/fping');

		/* Also check Cacti's configured fping path */
		$cacti_fping = read_config_option('path_fping');

		if (!empty($cacti_fping) && !in_array($cacti_fping, $candidates)) {
			array_unshift($candidates, $cacti_fping);
		}
	}

	foreach ($candidates as $path) {
		if (is_executable($path)) {
			return $path;
		}
	}

	return '';
}

/**
 * Get the list of TCP ports to probe.
 *
 * @return array of int
 */
function cereus_ipam_scan_get_tcp_ports() {
	$configured = read_config_option('cereus_ipam_scan_tcp_ports');

	if (!empty($configured)) {
		$ports = array();

		foreach (explode(',', $configured) as $p) {
			$p = (int) trim($p);

			if ($p > 0 && $p <= 65535) {
				$ports[] = $p;
			}
		}

		if (!empty($ports)) {
			return $ports;
		}
	}

	return array(80, 443, 22);
}

/**
 * Get scan timeout in milliseconds.
 *
 * @return int
 */
function cereus_ipam_scan_get_timeout() {
	$t = (int) read_config_option('cereus_ipam_scan_timeout');

	if ($t >= 100 && $t <= 30000) {
		return $t;
	}

	return 2000;
}

/**
 * Get platform-appropriate socket error codes.
 * Windows Winsock uses different error numbers than Unix.
 *
 * @return array with keys 'connrefused' and 'inprogress'
 */
function cereus_ipam_socket_error_codes() {
	global $config;

	if (isset($config['cacti_server_os']) && $config['cacti_server_os'] == 'win32') {
		return array(
			'connrefused' => array(defined('SOCKET_ECONNREFUSED') ? SOCKET_ECONNREFUSED : 10061, 10061),
			'inprogress'  => array(defined('SOCKET_EINPROGRESS') ? SOCKET_EINPROGRESS : 10036, 10036, 10035),
		);
	}

	return array(
		'connrefused' => array(defined('SOCKET_ECONNREFUSED') ? SOCKET_ECONNREFUSED : 111, 111),
		'inprogress'  => array(defined('SOCKET_EINPROGRESS') ? SOCKET_EINPROGRESS : 115, 115),
	);
}

/* ==================== Subnet Sweep ==================== */

/**
 * Run a ping sweep on a subnet.
 *
 * Dispatches to fping (from CLI/poller) or parallel TCP scan (from web)
 * based on the configured scan method.
 *
 * @param int $subnet_id
 * @return array
 */
function cereus_ipam_scan_ping($subnet_id) {
	global $config;

	$subnet = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));

	if (!cacti_sizeof($subnet)) {
		return array('success' => false, 'error' => 'Subnet not found');
	}

	$method = cereus_ipam_scan_get_method();

	if ($method === 'fping') {
		$fping_path = cereus_ipam_scan_find_fping();

		if (!empty($fping_path)) {
			$version = cereus_ipam_ip_version($subnet['subnet']);
			$cidr = $subnet['subnet'] . '/' . $subnet['mask'];

			/* Use fping6 for IPv6 subnets if available */
			if ($version == 6) {
				if ($config['cacti_server_os'] == 'win32') {
					$fping6 = dirname($fping_path) . '\\fping6.exe';
				} else {
					$fping6 = dirname($fping_path) . '/fping6';
				}

				if (is_executable($fping6)) {
					$fping_path = $fping6;
				}
			}

			return cereus_ipam_scan_fping($subnet_id, $subnet, $fping_path, $cidr);
		}

		/* fping not available, fall through to TCP */
	}

	return cereus_ipam_scan_tcp_parallel($subnet_id, $subnet);
}

/**
 * Subnet sweep using fping -g (ICMP).
 * Only works from CLI/poller context (not from web under SELinux httpd_t).
 */
function cereus_ipam_scan_fping($subnet_id, $subnet, $fping_path, $cidr) {
	global $config;

	$timeout = cereus_ipam_scan_get_timeout();
	$cmd = cacti_escapeshellcmd($fping_path) . ' -g -r 1 -t ' . (int) $timeout
		. ' ' . cacti_escapeshellarg($cidr);

	if ($config['cacti_server_os'] != 'win32') {
		$cmd .= ' 2>&1';
	}

	$output = array();
	exec($cmd, $output, $rc);

	$alive = array();
	$now = date('Y-m-d H:i:s');

	foreach ($output as $line) {
		$line = trim($line);

		/* fping output: "IP is alive" or "IP is unreachable" */
		if (preg_match('/^(\S+)\s+is\s+(alive|unreachable)/', $line, $m)) {
			$ip = $m[1];
			$is_alive = ($m[2] === 'alive') ? 1 : 0;

			if (!cereus_ipam_validate_ip($ip)) {
				continue;
			}

			if ($is_alive) {
				$alive[] = $ip;
			}

			/* Store scan result */
			db_execute_prepared("INSERT INTO plugin_cereus_ipam_scan_results
				(subnet_id, ip, is_alive, scan_type, scanned_at)
				VALUES (?, ?, ?, 'ping', ?)",
				array($subnet_id, $ip, $is_alive, $now));

			/* Try reverse DNS for alive hosts */
			if ($is_alive) {
				$hostname = @gethostbyaddr($ip);

				if ($hostname !== $ip && $hostname !== false) {
					db_execute_prepared("UPDATE plugin_cereus_ipam_scan_results
						SET hostname = ? WHERE subnet_id = ? AND ip = ? AND scanned_at = ?",
						array($hostname, $subnet_id, $ip, $now));
				}
			}
		}
	}

	/* Update subnet last_scanned */
	db_execute_prepared("UPDATE plugin_cereus_ipam_subnets SET last_scanned = NOW() WHERE id = ?", array($subnet_id));

	/* Run conflict detection after scan */
	cereus_ipam_post_scan_conflict_check($subnet_id);

	return array(
		'success'     => true,
		'alive_count' => count($alive),
		'alive_ips'   => $alive,
		'subnet'      => $cidr,
		'method'      => 'fping',
	);
}

/**
 * Parallel TCP connect scan for subnet sweep.
 * Uses non-blocking socket_create() + socket_select() for high performance.
 * Scans up to $batch_size IPs concurrently — a /24 finishes in ~timeout seconds.
 *
 * Works under SELinux httpd_t context (no raw sockets needed).
 * On Windows/IIS, requires the PHP sockets extension (php_sockets.dll).
 */
function cereus_ipam_scan_tcp_parallel($subnet_id, $subnet) {
	if (!function_exists('socket_create')) {
		return array(
			'success' => false,
			'error'   => __('PHP sockets extension is not loaded. Enable php_sockets.dll in php.ini for TCP scanning.', 'cereus_ipam'),
		);
	}

	$range = cereus_ipam_cidr_to_range($subnet['subnet'], $subnet['mask']);
	$version = cereus_ipam_ip_version($subnet['subnet']);
	$start = cereus_ipam_ip_to_gmp($range['first']);
	$end   = cereus_ipam_ip_to_gmp($range['last']);

	$total_size = gmp_intval(gmp_sub($end, $start)) + 1;

	/* Chunk size: process at most 256 IPs (/24) per chunk to keep
	 * memory and execution time bounded.  Large subnets (/16 = 65536 IPs)
	 * are scanned chunk by chunk instead of being silently truncated. */
	$chunk_size = 256;

	$ports = cereus_ipam_scan_get_tcp_ports();
	$timeout_ms = cereus_ipam_scan_get_timeout();
	$batch_size = 128;

	/* Suppress PHP warnings from socket functions */
	set_error_handler(function () { return true; });

	$alive_set = array(); /* ip => true */
	$now = date('Y-m-d H:i:s');

	/* Process the subnet in /24-sized chunks */
	$chunk_start = $start;
	$chunk_count = 0;

	while (gmp_cmp($chunk_start, $end) <= 0) {
		$chunk_end = gmp_add($chunk_start, $chunk_size - 1);

		if (gmp_cmp($chunk_end, $end) > 0) {
			$chunk_end = $end;
		}

		/* Heartbeat: refresh the scan-active timestamp every 10 chunks
		 * so progress polling knows the scan is still alive. */
		if (++$chunk_count % 10 === 0) {
			set_config_option('cereus_ipam_scan_active_' . $subnet_id, time());
		}

		/* Build IP list for this chunk */
		$chunk_ips = array();
		$current = $chunk_start;

		while (gmp_cmp($current, $chunk_end) <= 0) {
			$chunk_ips[] = cereus_ipam_gmp_to_ip($current, $version);
			$current = gmp_add($current, 1);
		}

		/* For each port, scan remaining (not-yet-found-alive) IPs in this chunk */
		foreach ($ports as $port) {
			$remaining = array_diff($chunk_ips, array_keys($alive_set));

			if (empty($remaining)) {
				break;
			}

			$remaining = array_values($remaining);

			for ($offset = 0; $offset < count($remaining); $offset += $batch_size) {
				$batch = array_slice($remaining, $offset, $batch_size);
				$batch_alive = cereus_ipam_tcp_connect_batch($batch, $port, $timeout_ms);

				foreach ($batch_alive as $ip) {
					$alive_set[$ip] = true;
				}
			}
		}

		/* Store results for this chunk immediately to avoid holding all IPs in memory */
		foreach ($chunk_ips as $ip) {
			$is_alive = isset($alive_set[$ip]) ? 1 : 0;

			db_execute_prepared("INSERT INTO plugin_cereus_ipam_scan_results
				(subnet_id, ip, is_alive, scan_type, scanned_at)
				VALUES (?, ?, ?, 'ping', ?)",
				array($subnet_id, $ip, $is_alive, $now));

			if ($is_alive) {
				$hostname = @gethostbyaddr($ip);

				if ($hostname !== $ip && $hostname !== false) {
					db_execute_prepared("UPDATE plugin_cereus_ipam_scan_results
						SET hostname = ? WHERE subnet_id = ? AND ip = ? AND scanned_at = ?",
						array($hostname, $subnet_id, $ip, $now));
				}
			}
		}

		/* Advance to next chunk */
		$chunk_start = gmp_add($chunk_end, 1);
	}

	restore_error_handler();

	/* Update subnet last_scanned */
	db_execute_prepared("UPDATE plugin_cereus_ipam_subnets SET last_scanned = NOW() WHERE id = ?", array($subnet_id));

	/* Run conflict detection after scan */
	cereus_ipam_post_scan_conflict_check($subnet_id);

	return array(
		'success'     => true,
		'alive_count' => count($alive_set),
		'alive_ips'   => array_keys($alive_set),
		'subnet'      => $subnet['subnet'] . '/' . $subnet['mask'],
		'total_ips'   => $total_size,
		'method'      => 'tcp-parallel',
	);
}

/**
 * Non-blocking TCP connect to a batch of IPs on one port.
 * Creates all sockets at once, connects non-blocking, then uses
 * socket_select() to wait for results. Returns alive IPs.
 *
 * @param array $ips       List of IP addresses
 * @param int   $port      TCP port to probe
 * @param int   $timeout_ms Timeout in milliseconds
 * @return array of alive IP strings
 */
function cereus_ipam_tcp_connect_batch($ips, $port, $timeout_ms) {
	$alive = array();
	$sockets = array();
	$socket_ips = array();
	$errcodes = cereus_ipam_socket_error_codes();

	foreach ($ips as $ip) {
		$af = (strpos($ip, ':') !== false) ? AF_INET6 : AF_INET;
		$sock = @socket_create($af, SOCK_STREAM, SOL_TCP);

		if (!$sock) {
			continue;
		}

		socket_set_nonblock($sock);
		$ret = @socket_connect($sock, $ip, $port);

		if ($ret === true) {
			/* Connected immediately */
			$alive[] = $ip;
			@socket_close($sock);
			continue;
		}

		$err = socket_last_error($sock);
		socket_clear_error($sock);

		if (in_array($err, $errcodes['connrefused'])) {
			/* Connection refused = host alive, port closed */
			$alive[] = $ip;
			@socket_close($sock);
			continue;
		}

		if (in_array($err, $errcodes['inprogress'])) {
			/* Connection in progress — add to select pool */
			$idx = count($sockets);
			$sockets[$idx] = $sock;
			$socket_ips[$idx] = $ip;
		} else {
			/* Immediate failure (no route, network unreachable) */
			@socket_close($sock);
		}
	}

	if (!empty($sockets)) {
		/* Wait for connections with socket_select() */
		$deadline = microtime(true) + ($timeout_ms / 1000);

		while (!empty($sockets) && microtime(true) < $deadline) {
			$remaining_us = max(0, (int) (($deadline - microtime(true)) * 1000000));
			$remaining_s  = (int) ($remaining_us / 1000000);
			$remaining_us = $remaining_us % 1000000;

			$r = null;
			$w = array_values($sockets);
			$e = array_values($sockets);

			$changed = @socket_select($r, $w, $e, $remaining_s, $remaining_us);

			if ($changed === false || $changed === 0) {
				break;
			}

			/* Check writable sockets — connection completed */
			foreach ($w as $sock) {
				$idx = array_search($sock, $sockets, true);

				if ($idx === false) {
					continue;
				}

				$so_err = @socket_get_option($sock, SOL_SOCKET, SO_ERROR);

				if ($so_err === 0 || in_array($so_err, $errcodes['connrefused'])) {
					/* Connected or connection refused — host is alive */
					$alive[] = $socket_ips[$idx];
				}

				@socket_close($sock);
				unset($sockets[$idx]);
				unset($socket_ips[$idx]);
			}

			/* Check exception sockets — connection failed */
			foreach ($e as $sock) {
				$idx = array_search($sock, $sockets, true);

				if ($idx === false) {
					continue;
				}

				@socket_close($sock);
				unset($sockets[$idx]);
				unset($socket_ips[$idx]);
			}
		}

		/* Close timed-out sockets */
		foreach ($sockets as $sock) {
			@socket_close($sock);
		}
	}

	return array_unique($alive);
}

/* ==================== Single Host Ping ==================== */

/**
 * Ping a single host. Returns true if alive, or an array with details.
 *
 * Uses TCP connect via PHP socket_create() (like Cacti's own ping_tcp).
 * Works under SELinux httpd_t — no raw sockets, no exec(), no log spam.
 *
 * @param string $ip      IP address to check
 * @param int    $timeout Timeout in seconds
 * @param bool   $details If true, return array with method/latency info
 * @return bool|array
 */
function cereus_ipam_ping_host($ip, $timeout = 1, $details = false) {
	if (!function_exists('socket_create')) {
		if ($details) {
			return array('alive' => false, 'method' => 'none', 'latency' => '', 'error' => 'sockets extension not loaded');
		}

		return false;
	}

	$ports = cereus_ipam_scan_get_tcp_ports();
	$timeout_ms = max(200, $timeout * 1000);

	/* Suppress PHP warnings from socket functions */
	set_error_handler(function () { return true; });

	$result = cereus_ipam_tcp_ping($ip, $ports, $timeout_ms);

	restore_error_handler();

	if ($result['alive']) {
		if ($details) {
			return $result;
		}

		return true;
	}

	if ($details) {
		return array('alive' => false, 'method' => 'none', 'latency' => '');
	}

	return false;
}

/**
 * TCP ping a single host using PHP socket_create() (non-blocking).
 * Tries each port until success or exhaustion.
 * Uses the same approach as Cacti's Net_Ping::ping_tcp().
 *
 * @param string $ip         IP address
 * @param array  $ports      TCP ports to try
 * @param int    $timeout_ms Timeout in milliseconds per port
 * @return array ['alive' => bool, 'method' => string, 'latency' => string, 'port' => int]
 */
function cereus_ipam_tcp_ping($ip, $ports, $timeout_ms) {
	$af = (strpos($ip, ':') !== false) ? AF_INET6 : AF_INET;
	$to_sec  = (int) ($timeout_ms / 1000);
	$to_usec = ($timeout_ms % 1000) * 1000;
	$errcodes = cereus_ipam_socket_error_codes();

	foreach ($ports as $port) {
		$sock = @socket_create($af, SOCK_STREAM, SOL_TCP);

		if (!$sock) {
			continue;
		}

		$start = microtime(true);

		socket_set_nonblock($sock);
		$ret = @socket_connect($sock, $ip, $port);

		if ($ret === true) {
			/* Connected immediately */
			$latency = round((microtime(true) - $start) * 1000, 1);
			@socket_close($sock);

			return array(
				'alive'   => true,
				'method'  => 'tcp',
				'latency' => $latency . ' ms',
				'port'    => $port,
			);
		}

		$err = socket_last_error($sock);
		socket_clear_error($sock);

		if (in_array($err, $errcodes['connrefused'])) {
			$latency = round((microtime(true) - $start) * 1000, 1);
			@socket_close($sock);

			return array(
				'alive'   => true,
				'method'  => 'tcp-rst',
				'latency' => $latency . ' ms',
				'port'    => $port,
			);
		}

		if (in_array($err, $errcodes['inprogress'])) {
			/* Wait for connection with socket_select() */
			$r = null;
			$w = array($sock);
			$e = array($sock);

			$changed = @socket_select($r, $w, $e, $to_sec, $to_usec);

			if ($changed > 0 && !empty($w)) {
				$so_err = @socket_get_option($sock, SOL_SOCKET, SO_ERROR);
				$latency = round((microtime(true) - $start) * 1000, 1);

				if ($so_err === 0) {
					@socket_close($sock);

					return array(
						'alive'   => true,
						'method'  => 'tcp',
						'latency' => $latency . ' ms',
						'port'    => $port,
					);
				}

				if (in_array($so_err, $errcodes['connrefused'])) {
					@socket_close($sock);

					return array(
						'alive'   => true,
						'method'  => 'tcp-rst',
						'latency' => $latency . ' ms',
						'port'    => $port,
					);
				}
			}
		}

		@socket_close($sock);
	}

	return array('alive' => false, 'method' => 'tcp', 'latency' => '');
}

/* ==================== ARP Scan (SNMP) ==================== */

/**
 * Run an ARP table scan via SNMP on Cacti devices within a subnet.
 * Walks ipNetToMediaTable (IPv4) and ipNetToPhysicalTable (IPv6).
 * Returns discovered IP+MAC pairs.
 */
function cereus_ipam_scan_arp($subnet_id) {
	$subnet = db_fetch_row_prepared("SELECT * FROM plugin_cereus_ipam_subnets WHERE id = ?", array($subnet_id));

	if (!cacti_sizeof($subnet)) {
		return array('success' => false, 'error' => 'Subnet not found');
	}

	$version = cereus_ipam_ip_version($subnet['subnet']);

	/* Find Cacti devices with SNMP that are UP or recovering */
	$hosts = db_fetch_assoc("SELECT id, hostname, description, snmp_community, snmp_version, snmp_username,
		snmp_password, snmp_auth_protocol, snmp_priv_passphrase, snmp_priv_protocol,
		snmp_context, snmp_engine_id, snmp_port, snmp_timeout, status
		FROM host WHERE disabled = '' AND status IN (2,3) AND snmp_version > 0");

	$gateway_hosts = array();
	$skipped_reasons = array();

	/* Resolve gateway IP once */
	$gateway_ip = '';
	if (!empty($subnet['gateway'])) {
		$gateway_ip = $subnet['gateway'];
		if (!cereus_ipam_validate_ip($gateway_ip)) {
			$resolved = @gethostbyname($gateway_ip);
			if (cereus_ipam_validate_ip($resolved)) {
				$gateway_ip = $resolved;
			}
		}
	}

	foreach ($hosts as $host) {
		$host_ip = $host['hostname'];

		if (!cereus_ipam_validate_ip($host_ip)) {
			$host_ip = @gethostbyname($host_ip);

			if (!cereus_ipam_validate_ip($host_ip)) {
				$skipped_reasons[] = $host['description'] . ' (' . $host['hostname'] . '): DNS resolution failed';
				continue;
			}
		}

		/* Include any device that could have ARP entries for this subnet:
		 * 1. Devices IN the subnet
		 * 2. The configured gateway (matched by resolved IP, not just hostname string)
		 * ARP tables on L3 devices contain entries for all directly-connected subnets,
		 * so the gateway router is the primary source even if it's outside the subnet. */
		if (cereus_ipam_ip_in_subnet($host_ip, $subnet['subnet'], $subnet['mask'])) {
			$gateway_hosts[] = $host;
		} elseif (!empty($gateway_ip) && $host_ip === $gateway_ip) {
			$gateway_hosts[] = $host;
		}
	}

	/* If no devices found, try broader matching for the gateway:
	 * 1. Match by hostname field = gateway value
	 * 2. Match by hostname field = gateway IP
	 * This covers cases where the gateway is entered as a DNS name but the
	 * Cacti device uses the IP as hostname, or vice versa. */
	if (!cacti_sizeof($gateway_hosts) && !empty($subnet['gateway'])) {
		$gw_search_values = array($subnet['gateway']);
		if (!empty($gateway_ip) && $gateway_ip !== $subnet['gateway']) {
			$gw_search_values[] = $gateway_ip;
		}

		foreach ($gw_search_values as $gw_val) {
			$gw_host = db_fetch_row_prepared("SELECT id, hostname, description, snmp_community, snmp_version, snmp_username,
				snmp_password, snmp_auth_protocol, snmp_priv_passphrase, snmp_priv_protocol,
				snmp_context, snmp_engine_id, snmp_port, snmp_timeout, status
				FROM host WHERE hostname = ? AND disabled = '' AND status IN (2,3) AND snmp_version > 0",
				array($gw_val));

			if (cacti_sizeof($gw_host)) {
				$gateway_hosts[] = $gw_host;
				break;
			}
		}
	}

	if (!cacti_sizeof($gateway_hosts)) {
		$hint = '';
		if (empty($subnet['gateway'])) {
			$hint = __(' Set the subnet gateway to a Cacti-managed router/switch that has ARP entries for this subnet.', 'cereus_ipam');
		} elseif (!empty($gateway_ip)) {
			$hint = __(' Gateway %s is not a Cacti device with SNMP, or it is down. Add it to Cacti with SNMP credentials and ensure it is UP.', $subnet['gateway'], 'cereus_ipam');
		}

		$error = __('No SNMP-capable devices found in subnet or as gateway.', 'cereus_ipam') . $hint;

		if (cacti_sizeof($skipped_reasons)) {
			$error .= ' ' . __('Skipped devices:', 'cereus_ipam') . ' ' . implode('; ', array_slice($skipped_reasons, 0, 5));
		}

		return array('success' => false, 'error' => $error);
	}

	$discovered = array();
	$now = date('Y-m-d H:i:s');

	foreach ($gateway_hosts as $host) {
		/* IPv4 ARP: ipNetToMediaTable (.1.3.6.1.2.1.4.22.1) */
		/* OID .1.3.6.1.2.1.4.22.1.2 = ipNetToMediaPhysAddress (indexed by ifIndex.ipAddr) */
		$arp_oid = '.1.3.6.1.2.1.4.22.1.2';

		$arp_results = cacti_snmp_walk(
			$host['hostname'], $host['snmp_community'],
			$arp_oid, $host['snmp_version'],
			$host['snmp_username'], $host['snmp_password'],
			$host['snmp_auth_protocol'], $host['snmp_priv_passphrase'],
			$host['snmp_priv_protocol'], $host['snmp_context'],
			$host['snmp_port'], $host['snmp_timeout'],
			read_config_option('snmp_retries'), SNMP_POLLER,
			$host['snmp_engine_id']
		);

		if (cacti_sizeof($arp_results)) {
			foreach ($arp_results as $entry) {
				/* OID format: .1.3.6.1.2.1.4.22.1.2.ifIndex.IP */
				$oid_parts = explode('.', $entry['oid']);
				/* Extract IP from last 4 octets of OID */
				$ip_parts = array_slice($oid_parts, -4);
				$ip = implode('.', $ip_parts);

				if (!cereus_ipam_validate_ip($ip)) {
					continue;
				}

				/* Only include IPs within our subnet */
				if (!cereus_ipam_ip_in_subnet($ip, $subnet['subnet'], $subnet['mask'])) {
					continue;
				}

				/* Parse MAC address from SNMP value */
				$mac = cereus_ipam_parse_snmp_mac($entry['value']);

				if (empty($mac)) {
					continue;
				}

				$discovered[$ip] = $mac;

				/* Insert scan result */
				db_execute_prepared("INSERT INTO plugin_cereus_ipam_scan_results
					(subnet_id, ip, is_alive, mac_address, scan_type, scanned_at)
					VALUES (?, ?, 1, ?, 'arp', ?)",
					array($subnet_id, $ip, $mac, $now));

				/* Try reverse DNS */
				$hostname = @gethostbyaddr($ip);

				if ($hostname !== $ip && $hostname !== false) {
					db_execute_prepared("UPDATE plugin_cereus_ipam_scan_results
						SET hostname = ? WHERE subnet_id = ? AND ip = ? AND scanned_at = ?",
						array($hostname, $subnet_id, $ip, $now));
				}
			}
		}

		/* IPv6 ARP: ipNetToPhysicalTable (.1.3.6.1.2.1.4.35.1) if version 6 subnet */
		if ($version == 6) {
			$ipv6_oid = '.1.3.6.1.2.1.4.35.1.4';
			$ipv6_results = cacti_snmp_walk(
				$host['hostname'], $host['snmp_community'],
				$ipv6_oid, $host['snmp_version'],
				$host['snmp_username'], $host['snmp_password'],
				$host['snmp_auth_protocol'], $host['snmp_priv_passphrase'],
				$host['snmp_priv_protocol'], $host['snmp_context'],
				$host['snmp_port'], $host['snmp_timeout'],
				read_config_option('snmp_retries'), SNMP_POLLER,
				$host['snmp_engine_id']
			);

			if (cacti_sizeof($ipv6_results)) {
				foreach ($ipv6_results as $entry) {
					$mac = cereus_ipam_parse_snmp_mac($entry['value']);

					if (empty($mac)) {
						continue;
					}

					/* Parse IPv6 from OID — more complex indexing, skip malformed */
					/* The OID includes ifIndex.addrType.addrLen.addr bytes */
					$oid_str = $entry['oid'];

					if (preg_match('/\.4\.35\.1\.4\.(\d+)\.2\.16\.(.+)$/', $oid_str, $m)) {
						$addr_bytes = explode('.', $m[2]);

						if (count($addr_bytes) == 16) {
							$hex_parts = array();

							for ($i = 0; $i < 16; $i += 2) {
								$hex_parts[] = sprintf('%02x%02x', (int) $addr_bytes[$i], (int) $addr_bytes[$i + 1]);
							}

							$ip = inet_ntop(hex2bin(implode('', $hex_parts)));

							if ($ip !== false && cereus_ipam_ip_in_subnet($ip, $subnet['subnet'], $subnet['mask'])) {
								$discovered[$ip] = $mac;

								db_execute_prepared("INSERT INTO plugin_cereus_ipam_scan_results
									(subnet_id, ip, is_alive, mac_address, scan_type, scanned_at)
									VALUES (?, ?, 1, ?, 'arp', ?)",
									array($subnet_id, $ip, $mac, $now));
							}
						}
					}
				}
			}
		}
	}

	/* Update MAC addresses in existing IPAM records */
	foreach ($discovered as $ip => $mac) {
		db_execute_prepared("UPDATE plugin_cereus_ipam_addresses
			SET mac_address = ?, last_seen = NOW()
			WHERE subnet_id = ? AND ip = ? AND (mac_address IS NULL OR mac_address = '')",
			array($mac, $subnet_id, $ip));
	}

	/* Update subnet last_scanned */
	db_execute_prepared("UPDATE plugin_cereus_ipam_subnets SET last_scanned = NOW() WHERE id = ?", array($subnet_id));

	return array(
		'success'    => true,
		'discovered' => count($discovered),
		'pairs'      => $discovered,
		'subnet'     => $subnet['subnet'] . '/' . $subnet['mask'],
	);
}

/* ==================== Utilities ==================== */

/**
 * Parse a MAC address from SNMP output.
 * Handles hex-string (0x001122334455), colon-separated hex, and space-separated hex.
 * Returns normalized XX:XX:XX:XX:XX:XX or empty string.
 */
function cereus_ipam_parse_snmp_mac($value) {
	$value = trim($value, " \t\n\r\0\x0B\"");

	/* Hex-STRING: "00 1A 2B 3C 4D 5E" or "00:1A:2B:3C:4D:5E" */
	if (preg_match('/^([0-9A-Fa-f]{2}[\s:\-]){5}[0-9A-Fa-f]{2}$/', $value)) {
		$clean = preg_replace('/[\s:\-]/', '', $value);

		return strtoupper(implode(':', str_split($clean, 2)));
	}

	/* 0x prefix hex */
	if (preg_match('/^0x([0-9A-Fa-f]{12})$/i', $value, $m)) {
		return strtoupper(implode(':', str_split($m[1], 2)));
	}

	/* Raw 6-byte binary might come through; try to detect */
	if (strlen($value) == 6 && !ctype_print($value)) {
		$hex = bin2hex($value);

		return strtoupper(implode(':', str_split($hex, 2)));
	}

	return '';
}

/**
 * Run scans for all subnets that are due.
 * Called from poller_bottom hook.
 */
function cereus_ipam_run_scheduled_scans() {
	if (!cereus_ipam_license_has_scanning()) {
		return;
	}

	$subnets = db_fetch_assoc("SELECT * FROM plugin_cereus_ipam_subnets
		WHERE scan_enabled = 1
		AND (last_scanned IS NULL OR UNIX_TIMESTAMP(NOW()) - UNIX_TIMESTAMP(last_scanned) >= scan_interval)");

	if (!cacti_sizeof($subnets)) {
		return;
	}

	foreach ($subnets as $subnet) {
		if (function_exists('cereus_ipam_should_suppress_scan') && cereus_ipam_should_suppress_scan($subnet['id'])) {
			continue;
		}

		cereus_ipam_scan_ping($subnet['id']);
	}
}

/**
 * Post-scan conflict check.
 * Loads conflicts lib, runs detection, and sends alerts if configured.
 *
 * @param int $subnet_id
 */
function cereus_ipam_post_scan_conflict_check($subnet_id) {
	global $config;

	$conflicts_file = $config['base_path'] . '/plugins/cereus_ipam/lib/conflicts.php';

	if (!file_exists($conflicts_file)) {
		return;
	}

	include_once($conflicts_file);

	$new_conflicts = cereus_ipam_detect_conflicts($subnet_id);

	/* Send alert if conflict alerting is enabled */
	$alert_enabled = read_config_option('cereus_ipam_conflict_alerts_enabled');

	if ($alert_enabled == 'on' && cacti_sizeof($new_conflicts)) {
		/* Filter out false (duplicates) */
		$real_new = array_filter($new_conflicts);

		if (cacti_sizeof($real_new)) {
			cereus_ipam_conflict_alert($real_new, $subnet_id);
		}
	}
}
