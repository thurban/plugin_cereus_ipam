<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2024-2026 Urban-Software.de / Thomas Urban               |
 +-------------------------------------------------------------------------+
 | Cereus IPAM - Webhook Callbacks (Enterprise)                            |
 +-------------------------------------------------------------------------+
*/

/**
 * Dispatch a webhook event to all configured URLs.
 *
 * Enterprise tier feature gated by cereus_ipam_license_has_webhooks().
 *
 * @param string $event_type  The event type (e.g. create, update, delete)
 * @param string $object_type The object type (e.g. subnet, address, vlan)
 * @param int    $object_id   The ID of the affected object
 * @param array  $data        Additional event data
 */
function cereus_ipam_webhook_dispatch($event_type, $object_type, $object_id, $data) {
	/* Check license gate */
	if (!function_exists('cereus_ipam_license_has_webhooks') || !cereus_ipam_license_has_webhooks()) {
		return;
	}

	/* Check if webhooks are enabled */
	$enabled = read_config_option('cereus_ipam_webhook_enabled');

	if (empty($enabled)) {
		return;
	}

	/* Get webhook URLs */
	$urls_raw = read_config_option('cereus_ipam_webhook_urls');

	if (empty($urls_raw)) {
		return;
	}

	$urls = explode("\n", $urls_raw);

	/* Build payload */
	$payload = json_encode(array(
		'event'       => $event_type,
		'object_type' => $object_type,
		'object_id'   => $object_id,
		'data'        => $data,
		'timestamp'   => date('c'),
		'source'      => 'cereus_ipam',
	), JSON_UNESCAPED_SLASHES);

	/* Send to each URL */
	foreach ($urls as $url) {
		$url = trim($url);

		if (empty($url)) {
			continue;
		}

		$ch = curl_init($url);

		curl_setopt_array($ch, array(
			CURLOPT_POST           => true,
			CURLOPT_POSTFIELDS     => $payload,
			CURLOPT_HTTPHEADER     => array('Content-Type: application/json'),
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_TIMEOUT        => 5,
		));

		$response  = curl_exec($ch);
		$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		$error     = curl_error($ch);

		curl_close($ch);

		if ($error !== '') {
			cacti_log('CEREUS IPAM WEBHOOK: Failed to dispatch to ' . $url . ' - ' . $error, false, 'PLUGIN');
		} else {
			cacti_log('CEREUS IPAM WEBHOOK: Dispatched ' . $event_type . '/' . $object_type . '/' . $object_id . ' to ' . $url . ' (HTTP ' . $http_code . ')', false, 'PLUGIN');
		}
	}
}

/**
 * Send a test webhook to a given URL.
 *
 * @param string $url The URL to send the test webhook to
 *
 * @return array  Result with keys: success (bool), http_code (int), error (string)
 */
function cereus_ipam_webhook_test($url) {
	$payload = json_encode(array(
		'event'       => 'test',
		'object_type' => 'test',
		'object_id'   => 0,
		'data'        => array('message' => 'Cereus IPAM webhook test'),
		'timestamp'   => date('c'),
		'source'      => 'cereus_ipam',
	), JSON_UNESCAPED_SLASHES);

	$ch = curl_init($url);

	curl_setopt_array($ch, array(
		CURLOPT_POST           => true,
		CURLOPT_POSTFIELDS     => $payload,
		CURLOPT_HTTPHEADER     => array('Content-Type: application/json'),
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_TIMEOUT        => 5,
	));

	$response  = curl_exec($ch);
	$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
	$error     = curl_error($ch);

	curl_close($ch);

	$success = ($error === '' && $http_code >= 200 && $http_code < 300);

	return array(
		'success'   => $success,
		'http_code' => $http_code,
		'error'     => $error,
	);
}
