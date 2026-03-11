<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2024-2026 Urban-Software.de / Thomas Urban               |
 +-------------------------------------------------------------------------+
 | Cereus IPAM - Webhook Test AJAX Endpoint                                |
 +-------------------------------------------------------------------------+
*/

chdir('../../');
include('./include/auth.php');
include_once('./plugins/cereus_ipam/lib/license_check.php');
include_once('./plugins/cereus_ipam/lib/webhooks.php');

header('Content-Type: application/json');

if (!cereus_ipam_license_has_webhooks()) {
	print json_encode(array('success' => false, 'error' => 'Enterprise license required'));
	exit;
}

$url = trim(get_nfilter_request_var('url', ''));

if (empty($url)) {
	print json_encode(array('success' => false, 'error' => 'No URL provided'));
	exit;
}

if (!filter_var($url, FILTER_VALIDATE_URL)) {
	print json_encode(array('success' => false, 'error' => 'Invalid URL'));
	exit;
}

$result = cereus_ipam_webhook_test($url);

print json_encode($result);
