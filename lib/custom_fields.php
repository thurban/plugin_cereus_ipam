<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2024-2026 Urban-Software.de / Thomas Urban               |
 +-------------------------------------------------------------------------+
 | Cereus IPAM - Custom Fields Library                                     |
 +-------------------------------------------------------------------------+
*/

/**
 * Fetch custom field definitions for a given entity type.
 *
 * @param  string $applies_to  One of 'subnet', 'address', 'vlan'.
 * @return array  Rows from plugin_cereus_ipam_custom_fields ordered by display_order.
 */
function cereus_ipam_get_custom_fields($applies_to) {
	return db_fetch_assoc_prepared("SELECT *
		FROM plugin_cereus_ipam_custom_fields
		WHERE applies_to = ?
		ORDER BY display_order, name",
		array($applies_to));
}

/**
 * Render custom fields as a draw_edit_form-compatible field definition array.
 *
 * Returns an array keyed by 'cf_<field_name>' that can be merged into an
 * existing $fields array before passing to draw_edit_form().
 *
 * @param  string $applies_to      One of 'subnet', 'address', 'vlan'.
 * @param  array  $current_values  Associative array of current values (from JSON decode of the entity's custom_fields column).
 * @return array  Field definitions suitable for draw_edit_form.
 */
function cereus_ipam_render_custom_fields($applies_to, $current_values) {
	$fields = array();
	$custom_fields = cereus_ipam_get_custom_fields($applies_to);

	if (!cacti_sizeof($custom_fields)) {
		return $fields;
	}

	if (!is_array($current_values)) {
		$current_values = array();
	}

	foreach ($custom_fields as $cf) {
		$key   = 'cf_' . $cf['name'];
		$value = isset($current_values[$cf['name']]) ? $current_values[$cf['name']] : '';

		$field = array(
			'friendly_name' => $cf['label'],
			'description'   => '',
			'value'         => $value,
		);

		switch ($cf['type']) {
			case 'text':
				$field['method']    = 'textbox';
				$field['max_length'] = 255;
				$field['size']      = 60;
				break;

			case 'textarea':
				$field['method']      = 'textarea';
				$field['textarea_rows'] = 4;
				$field['textarea_cols'] = 60;
				break;

			case 'dropdown':
				$options = array('' => __('None', 'cereus_ipam'));
				$parsed  = json_decode($cf['options'], true);
				if (is_array($parsed)) {
					foreach ($parsed as $opt) {
						$options[$opt] = $opt;
					}
				}
				$field['method'] = 'drop_array';
				$field['array']  = $options;
				$field['default'] = '';
				break;

			case 'checkbox':
				$field['method'] = 'checkbox';
				$field['value']  = ($value === 'on' || $value === '1' || $value === true) ? 'on' : '';
				break;

			case 'date':
				$field['method']      = 'textbox';
				$field['max_length']  = 10;
				$field['size']        = 12;
				$field['placeholder'] = 'YYYY-MM-DD';
				break;

			case 'url':
				$field['method']     = 'textbox';
				$field['max_length'] = 2048;
				$field['size']       = 60;
				break;

			default:
				$field['method']     = 'textbox';
				$field['max_length'] = 255;
				$field['size']       = 60;
				break;
		}

		$fields[$key] = $field;
	}

	return $fields;
}

/**
 * Collect custom field values from POST data and return a JSON string for storage.
 *
 * Reads all cf_ prefixed request vars for the given entity type, validates
 * required fields, sanitizes input, and returns a JSON-encoded string.
 *
 * @param  string $applies_to  One of 'subnet', 'address', 'vlan'.
 * @return string JSON-encoded custom field values.
 */
function cereus_ipam_save_custom_fields($applies_to) {
	$custom_fields = cereus_ipam_get_custom_fields($applies_to);
	$values = array();

	if (!cacti_sizeof($custom_fields)) {
		return json_encode($values);
	}

	foreach ($custom_fields as $cf) {
		$key = 'cf_' . $cf['name'];

		if ($cf['type'] === 'checkbox') {
			$raw = get_nfilter_request_var($key);
			$values[$cf['name']] = ($raw === 'on') ? 'on' : '';
		} else {
			$raw = get_nfilter_request_var($key);
			$val = cereus_ipam_sanitize_text($raw);

			if ($cf['required'] && $val === '') {
				raise_message('custom_field_required',
					__('Custom field "%s" is required.', $cf['label'], 'cereus_ipam'),
					MESSAGE_LEVEL_ERROR);
			}

			$values[$cf['name']] = $val;
		}
	}

	return json_encode($values);
}

/**
 * Return display_text column definitions for custom fields in list views.
 *
 * Each entry is an array with 'display' and 'align' keys, suitable for
 * merging into a Cacti html_header_sort column array.
 *
 * @param  string $applies_to  One of 'subnet', 'address', 'vlan'.
 * @return array  Array of column definitions keyed by 'cf_<field_name>'.
 */
function cereus_ipam_display_custom_fields_columns($applies_to) {
	$columns = array();
	$custom_fields = cereus_ipam_get_custom_fields($applies_to);

	if (!cacti_sizeof($custom_fields)) {
		return $columns;
	}

	foreach ($custom_fields as $cf) {
		$key = 'cf_' . $cf['name'];
		$columns[$key] = array(
			'display' => $cf['label'],
			'align'   => 'left',
		);
	}

	return $columns;
}

/**
 * Format a single custom field value for display in a list view cell.
 *
 * @param  array  $field  The field definition row from plugin_cereus_ipam_custom_fields.
 * @param  mixed  $value  The stored value for this field.
 * @return string HTML-safe display string.
 */
function cereus_ipam_display_custom_field_value($field, $value) {
	if ($value === null || $value === '') {
		return '';
	}

	switch ($field['type']) {
		case 'checkbox':
			return ($value === 'on' || $value === '1' || $value === true)
				? __('Yes', 'cereus_ipam')
				: __('No', 'cereus_ipam');

		case 'url':
			$escaped = html_escape($value);
			return '<a href="' . $escaped . '" target="_blank" rel="noopener noreferrer">' . $escaped . '</a>';

		default:
			return html_escape($value);
	}
}
