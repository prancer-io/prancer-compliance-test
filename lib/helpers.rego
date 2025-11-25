# Prancer Compliance Test - Helper Functions Library
#
# Common utility functions used across compliance policies.
#
# Usage:
#   import data.lib.helpers

package lib.helpers

##############################################################################
# PROPERTY ACCESS HELPERS
##############################################################################

# Check if an object has a specific property
# Args:
#   parent_object: The object to check
#   target_property: The property name to look for
# Returns:
#   true if property exists
has_property(parent_object, target_property) {
    _ = parent_object[target_property]
}

# Get property value with default fallback
# Args:
#   obj: The object
#   prop: The property name
#   default_value: Value to return if property doesn't exist
# Returns:
#   Property value or default
get_property(obj, prop, default_value) = value {
    has_property(obj, prop)
    value := obj[prop]
} else = default_value {
    true
}

# Get nested property safely
# Args:
#   obj: The root object
#   path: Dot-separated path string (e.g., "properties.securityRules")
#   default_value: Value to return if path doesn't exist
# Returns:
#   Value at path or default
get_nested_property(obj, path, default_value) = value {
    parts := split(path, ".")
    value := traverse_path(obj, parts)
} else = default_value {
    true
}

# Internal helper to traverse object path
traverse_path(obj, path) = obj {
    count(path) == 0
}

traverse_path(obj, path) = result {
    count(path) > 0
    key := path[0]
    remaining := array.slice(path, 1, count(path))
    result := traverse_path(obj[key], remaining)
}

##############################################################################
# STRING HELPERS
##############################################################################

# Case-insensitive string comparison
# Args:
#   a: First string
#   b: Second string
# Returns:
#   true if strings are equal (case-insensitive)
lower_equals(a, b) {
    lower(a) == lower(b)
}

# Check if string contains substring (case-insensitive)
# Args:
#   str: The string to search in
#   substr: The substring to find
# Returns:
#   true if substr is found in str
lower_contains(str, substr) {
    contains(lower(str), lower(substr))
}

# Check if string starts with prefix (case-insensitive)
# Args:
#   str: The string to check
#   prefix: The prefix to look for
# Returns:
#   true if str starts with prefix
lower_startswith(str, prefix) {
    startswith(lower(str), lower(prefix))
}

# Check if string ends with suffix (case-insensitive)
# Args:
#   str: The string to check
#   suffix: The suffix to look for
# Returns:
#   true if str ends with suffix
lower_endswith(str, suffix) {
    endswith(lower(str), lower(suffix))
}

##############################################################################
# ARRAY HELPERS
##############################################################################

# Check if array contains element (case-insensitive for strings)
# Args:
#   target_array: Array to search
#   element: Element to find
# Returns:
#   true if element found, false otherwise
array_contains(target_array, element) = true {
    lower(target_array[_]) == lower(element)
} else = false {
    true
}

# Check if any array element contains a substring
# Args:
#   target_array: Array of strings
#   substring: Substring to find
# Returns:
#   true if any element contains substring
array_element_contains(target_array, substring) = true {
    contains(lower(target_array[_]), lower(substring))
} else = false {
    true
}

# Check if any element from target_array exists in match_array
# Args:
#   target_array: Array to check
#   match_array: Array to match against
# Returns:
#   true if any element matches
array_intersects(target_array, match_array) = true {
    lower(target_array[_]) == lower(match_array[_])
} else = false {
    true
}

# Get array length safely (returns 0 if not an array or doesn't exist)
# Args:
#   arr: The array
# Returns:
#   Integer length
safe_count(arr) = cnt {
    cnt := count(arr)
} else = 0 {
    true
}

# Check if array is empty or doesn't exist
# Args:
#   arr: The array to check
# Returns:
#   true if array is empty or undefined
is_empty_or_undefined(arr) {
    not arr
}

is_empty_or_undefined(arr) {
    count(arr) == 0
}

##############################################################################
# NETWORK/CIDR HELPERS
##############################################################################

# Check if CIDR represents all addresses (0.0.0.0/0 or ::/0)
# Args:
#   cidr: CIDR string
# Returns:
#   true if CIDR allows all addresses
is_cidr_open(cidr) {
    cidr == "0.0.0.0/0"
}

is_cidr_open(cidr) {
    cidr == "::/0"
}

is_cidr_open(cidr) {
    lower(cidr) == "*"
}

is_cidr_open(cidr) {
    lower(cidr) == "any"
}

# Check if source address represents all addresses
# Args:
#   source: Source address string
# Returns:
#   true if source allows all addresses
is_source_open(source) {
    is_cidr_open(source)
}

is_source_open(source) {
    lower(source) == "internet"
}

# Check if port range includes a specific port
# Args:
#   from_port: Start of range
#   to_port: End of range
#   target_port: Port to check
# Returns:
#   true if target_port is in range
port_in_range(from_port, to_port, target_port) {
    to_number(from_port) <= target_port
    to_number(to_port) >= target_port
}

# Check if port allows all (*, -1, or 0-65535)
# Args:
#   port: Port value to check
# Returns:
#   true if port represents all ports
is_port_all(port) {
    port == "*"
}

is_port_all(port) {
    port == "-1"
}

is_port_all(port) {
    to_number(port) == -1
}

##############################################################################
# TYPE CONVERSION HELPERS
##############################################################################

# Safe conversion to number with default
# Args:
#   val: Value to convert
#   default_val: Default if conversion fails
# Returns:
#   Numeric value
to_number_safe(val, default_val) = num {
    num := to_number(val)
} else = default_val {
    true
}

# Convert boolean-like values to boolean
# Args:
#   val: Value to convert
# Returns:
#   true/false
to_bool(val) = true {
    val == true
}

to_bool(val) = true {
    lower(val) == "true"
}

to_bool(val) = true {
    val == 1
}

to_bool(val) = false {
    val == false
}

to_bool(val) = false {
    lower(val) == "false"
}

to_bool(val) = false {
    val == 0
}

##############################################################################
# AZURE SPECIFIC HELPERS
##############################################################################

# Extract resource name from Azure resource ID
# Args:
#   resource_id: Full Azure resource ID
# Returns:
#   Resource name
azure_resource_name(resource_id) = name {
    parts := split(resource_id, "/")
    name := parts[count(parts) - 1]
}

# Extract resource group from Azure resource ID
# Args:
#   resource_id: Full Azure resource ID
# Returns:
#   Resource group name
azure_resource_group(resource_id) = rg {
    parts := split(resource_id, "/")
    some i
    lower(parts[i]) == "resourcegroups"
    rg := parts[i + 1]
}

# Check if Azure resource is in a specific resource group
# Args:
#   resource: Azure resource object
#   rg_name: Resource group name to match
# Returns:
#   true if resource is in the specified RG
azure_in_resource_group(resource, rg_name) {
    rg := azure_resource_group(resource.id)
    lower(rg) == lower(rg_name)
}

##############################################################################
# AWS SPECIFIC HELPERS
##############################################################################

# Extract account ID from AWS ARN
# Args:
#   arn: AWS ARN string
# Returns:
#   Account ID
aws_account_id(arn) = account {
    parts := split(arn, ":")
    account := parts[4]
}

# Extract region from AWS ARN
# Args:
#   arn: AWS ARN string
# Returns:
#   AWS region
aws_region(arn) = region {
    parts := split(arn, ":")
    region := parts[3]
}

# Extract service from AWS ARN
# Args:
#   arn: AWS ARN string
# Returns:
#   AWS service name
aws_service(arn) = service {
    parts := split(arn, ":")
    service := parts[2]
}

##############################################################################
# VALIDATION HELPERS
##############################################################################

# Check if value is a non-empty string
# Args:
#   val: Value to check
# Returns:
#   true if non-empty string
is_non_empty_string(val) {
    is_string(val)
    count(val) > 0
}

# Check if value is a valid port number
# Args:
#   port: Port value
# Returns:
#   true if valid port (1-65535)
is_valid_port(port) {
    num := to_number(port)
    num >= 1
    num <= 65535
}

# Check if value looks like an IP address
# Args:
#   val: Value to check
# Returns:
#   true if appears to be IP address
looks_like_ip(val) {
    regex.match(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, val)
}

# Check if value looks like CIDR notation
# Args:
#   val: Value to check
# Returns:
#   true if appears to be CIDR
looks_like_cidr(val) {
    regex.match(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$`, val)
}
