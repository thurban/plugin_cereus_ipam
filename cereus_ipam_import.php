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
 | Cereus IPAM - CSV Import UI                                             |
 +-------------------------------------------------------------------------+
*/

chdir('../../');
include('./include/auth.php');
include_once('./plugins/cereus_ipam/includes/constants.php');
include_once('./plugins/cereus_ipam/lib/license_check.php');
include_once('./plugins/cereus_ipam/lib/validation.php');
include_once('./plugins/cereus_ipam/lib/ip_utils.php');
include_once('./plugins/cereus_ipam/lib/functions.php');
include_once('./plugins/cereus_ipam/lib/changelog.php');
include_once('./plugins/cereus_ipam/lib/import_export.php');

$action = get_nfilter_request_var('action', '');

switch ($action) {
	case 'import':
		cereus_ipam_do_import();
		break;
	default:
		top_header();
		cereus_ipam_import_form();
		bottom_footer();
		break;
}

/* ==================== Import Processing ==================== */

function cereus_ipam_do_import() {
	$subnet_id = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);
	$format = get_nfilter_request_var('import_format', 'auto');
	if (!in_array($format, array('auto', 'cereus', 'phpipam', 'netbox'))) {
		$format = 'auto';
	}

	if (!$subnet_id) {
		raise_message('cereus_ipam_nosub', __('No subnet selected.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_import.php');
		exit;
	}

	/* Validate file upload */
	if (!isset($_FILES['import_file']) || $_FILES['import_file']['error'] !== UPLOAD_ERR_OK) {
		$err_msg = __('File upload failed.', 'cereus_ipam');
		if (isset($_FILES['import_file'])) {
			switch ($_FILES['import_file']['error']) {
				case UPLOAD_ERR_INI_SIZE:
				case UPLOAD_ERR_FORM_SIZE:
					$err_msg = __('File too large.', 'cereus_ipam');
					break;
				case UPLOAD_ERR_NO_FILE:
					$err_msg = __('No file selected.', 'cereus_ipam');
					break;
			}
		}
		raise_message('cereus_ipam_upload', $err_msg, MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_import.php?subnet_id=' . $subnet_id);
		exit;
	}

	$file = $_FILES['import_file'];

	/* Extension check */
	$ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
	if ($ext !== 'csv') {
		raise_message('cereus_ipam_ext', __('Only .csv files are allowed.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_import.php?subnet_id=' . $subnet_id);
		exit;
	}

	/* MIME type check */
	$allowed_mime = array('text/csv', 'text/plain', 'application/csv', 'application/vnd.ms-excel');
	if (!in_array($file['type'], $allowed_mime)) {
		raise_message('cereus_ipam_mime', __('Invalid file type. Only CSV files are accepted.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_import.php?subnet_id=' . $subnet_id);
		exit;
	}

	/* Size check */
	$max_mb = (int) read_config_option('cereus_ipam_import_max_size');
	if ($max_mb <= 0) {
		$max_mb = 5;
	}
	$max_bytes = $max_mb * 1024 * 1024;
	if ($file['size'] > $max_bytes) {
		raise_message('cereus_ipam_size', __('File exceeds maximum size of %d MB.', $max_mb, 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_import.php?subnet_id=' . $subnet_id);
		exit;
	}

	/* Move to temp directory */
	$tmp_path = sys_get_temp_dir() . '/cereus_ipam_' . uniqid() . '.csv';
	if (!move_uploaded_file($file['tmp_name'], $tmp_path)) {
		raise_message('cereus_ipam_move', __('Failed to process uploaded file.', 'cereus_ipam'), MESSAGE_LEVEL_ERROR);
		header('Location: cereus_ipam_import.php?subnet_id=' . $subnet_id);
		exit;
	}

	/* Run import */
	$result = cereus_ipam_import_csv($subnet_id, $tmp_path, $format);

	/* Cleanup temp file */
	@unlink($tmp_path);

	if ($result['success']) {
		$msg = __('Import complete: %d imported, %d skipped.', $result['imported'], $result['skipped'], 'cereus_ipam');
		if (count($result['errors']) > 0) {
			$msg .= ' ' . __('Errors: %d', count($result['errors']), 'cereus_ipam');
		}
		raise_message('cereus_ipam_imported', $msg, MESSAGE_LEVEL_INFO);

		/* Store errors in session for display */
		if (count($result['errors']) > 0) {
			$_SESSION['cereus_ipam_import_errors'] = $result['errors'];
		}
	} else {
		raise_message('cereus_ipam_import_fail', $result['error'], MESSAGE_LEVEL_ERROR);
	}

	header('Location: cereus_ipam_import.php?subnet_id=' . $subnet_id);
	exit;
}

/* ==================== Import Form ==================== */

function cereus_ipam_import_form() {
	$subnet_id = get_filter_request_var('subnet_id', FILTER_VALIDATE_INT);

	/* Subnet selector */
	$subnets = db_fetch_assoc("SELECT s.id, CONCAT(s.subnet, '/', s.mask) AS cidr, s.description, sec.name AS section_name
		FROM plugin_cereus_ipam_subnets s
		LEFT JOIN plugin_cereus_ipam_sections sec ON sec.id = s.section_id
		ORDER BY sec.name, s.subnet");

	$max_rows = cereus_ipam_license_max_import_rows();
	$max_text = ($max_rows > 0) ? __('Max %d rows (Community)', $max_rows, 'cereus_ipam') : __('Unlimited rows', 'cereus_ipam');

	html_start_box(__('CSV Import', 'cereus_ipam') . ' - ' . $max_text, '100%', '', '3', 'center', '');

	print '<tr class="even"><td style="padding:15px;">';
	print '<form method="post" action="cereus_ipam_import.php" enctype="multipart/form-data">';

	print '<table class="filterTable">';

	/* Subnet selector */
	print '<tr>';
	print '<td><b>' . __('Target Subnet', 'cereus_ipam') . ':</b></td>';
	print '<td><select name="subnet_id" id="subnet_id">';
	print '<option value="">' . __('Select a subnet...', 'cereus_ipam') . '</option>';
	foreach ($subnets as $s) {
		$label = $s['cidr'] . ' - ' . $s['description'] . ' (' . $s['section_name'] . ')';
		print "<option value='" . $s['id'] . "'" . ($subnet_id == $s['id'] ? ' selected' : '') . ">" . html_escape($label) . "</option>\n";
	}
	print '</select></td>';
	print '</tr>';

	/* File input */
	print '<tr>';
	print '<td><b>' . __('CSV File', 'cereus_ipam') . ':</b></td>';
	print '<td><input type="file" name="import_file" accept=".csv"></td>';
	print '</tr>';

	/* Format selector */
	print '<tr>';
	print '<td><b>' . __('CSV Format', 'cereus_ipam') . ':</b></td>';
	print '<td><select name="import_format" id="import_format">';
	print '<option value="auto">' . __('Auto-Detect', 'cereus_ipam') . '</option>';
	print '<option value="cereus">' . __('Cereus IPAM (Native)', 'cereus_ipam') . '</option>';
	print '<option value="phpipam">' . __('phpIPAM Export', 'cereus_ipam') . '</option>';
	print '<option value="netbox">' . __('NetBox Export', 'cereus_ipam') . '</option>';
	print '</select></td>';
	print '</tr>';

	/* Submit */
	print '<tr>';
	print '<td></td>';
	print '<td>';
	print '<input type="hidden" name="action" value="import">';
	print '<input type="submit" class="ui-button ui-corner-all ui-widget" value="' . __esc('Import', 'cereus_ipam') . '">';
	print ' <a class="linkEditMain" href="cereus_ipam.php">' . __('Cancel', 'cereus_ipam') . '</a>';
	print '</td>';
	print '</tr>';

	print '</table>';
	print '</form>';
	print '</td></tr>';

	/* Expected format */
	print '<tr class="odd"><td style="padding:8px 15px;">';
	print '<b>' . __('Expected CSV Formats', 'cereus_ipam') . ':</b><br><br>';

	print '<b>' . __('Cereus IPAM (Native)', 'cereus_ipam') . ':</b><br>';
	print '<code>ip,hostname,description,mac_address,state,owner,device_type,note</code><br><br>';

	print '<b>' . __('phpIPAM Export', 'cereus_ipam') . ':</b><br>';
	print '<code>ip_addr,hostname,description,mac,owner,state,switch,port,note</code><br><br>';

	print '<b>' . __('NetBox Export', 'cereus_ipam') . ':</b><br>';
	print '<code>address,vrf,tenant,status,role,dns_name,description,tags</code><br><br>';

	print '<small>' . __('Only the IP column is required. Other columns are optional. Auto-detect identifies the format by header names.', 'cereus_ipam') . '</small><br>';
	print '<small>' . __('Valid states: active, reserved, dhcp, offline, available', 'cereus_ipam') . '</small>';
	print '</td></tr>';

	html_end_box();

	/* Show previous import errors if any */
	if (isset($_SESSION['cereus_ipam_import_errors']) && count($_SESSION['cereus_ipam_import_errors']) > 0) {
		html_start_box(__('Import Errors', 'cereus_ipam'), '100%', '', '3', 'center', '');
		print '<tr class="even"><td style="padding:8px 15px;">';
		print '<ul>';
		foreach ($_SESSION['cereus_ipam_import_errors'] as $err) {
			print '<li>' . html_escape($err) . '</li>';
		}
		print '</ul>';
		print '</td></tr>';
		html_end_box();

		unset($_SESSION['cereus_ipam_import_errors']);
	}
}
