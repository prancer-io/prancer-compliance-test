package common

# True iff a value is non-empty (string, array, object).
non_empty(x) {
  x != null
  not x == ""
}
non_empty(x) {
  count(x) > 0
}

# Normalize case-insensitive string comparison.
eq_fold(a, b) {
  lower(a) == lower(b)
}

ends_with_fold(s, suffix) {
  endswith(lower(s), lower(suffix))
}

# Input shape helpers (customize to your engine/input):
is_type(res, t) {
  lower(res.type) == lower(t)
}

# Safe getter pattern (avoid crashes if missing):
get(obj, key, fallback) = v {
  v := object.get(obj, key, fallback)
}

# Existence check for a single resource input:
resource_exists = true {
  input != null
  input.name
} else = false {
  true
}

# Safe access to nested properties
get_nested(obj, path, fallback) = v {
  v := object.get(obj, path, fallback)
} else = fallback {
  true
}

# Check if a field exists and is not null
field_exists(obj, field) {
  obj[field] != null
}

# Safe boolean conversion
to_bool(val) = true {
  val == true
} else = true {
  lower(val) == "true"
} else = false {
  val == false
} else = false {
  lower(val) == "false"
} else = false {
  true
}

# Case-insensitive array containment check
array_contains(arr, elem) {
  lower(arr[_]) == lower(elem)
}

# Case-insensitive check if any array element contains a substring
array_element_contains(arr, substr) {
  contains(lower(arr[_]), lower(substr))
}

# Check if any element of target_array matches any element of in_array (case-insensitive)
array_element_in(target_array, in_array) {
  lower(target_array[_]) == lower(in_array[_])
}

# Check if any element of target_array contains any element of in_array (case-insensitive)
array_element_contains_in(target_array, in_array) {
  contains(lower(target_array[_]), lower(in_array[_]))
}

# ===== Named Constants =====

# Rotation / expiration periods
ninety_days_seconds := 7776000            # 90 * 24 * 60 * 60
ninety_days_nanoseconds := 7776000000000000  # 90 * 24 * 60 * 60 * 1_000_000_000

# has_property - check if an object has a given property
has_property(obj, prop) {
  _ = obj[prop]
}
