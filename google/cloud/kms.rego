package rule

import data.common

#
# PR-GCP-CLD-KMS-001
#

# === Outcome ===
default pass = false
default fail = false
default skip = false
default message = "GCP KMS encryption key must rotate within 90 days; found non-compliant rotation period."

# Scope to GCP KMS crypto keys that exist
in_scope {
    common.resource_exists
    common.non_empty(common.get(input, "name", ""))
    common.get(input, "purpose", "") == "ENCRYPT_DECRYPT"
}

# Maximum allowed rotation period (90 days in seconds)
max_rotation_period := common.ninety_days_seconds

# Check for violations
violation {
    in_scope
    rotation_period := common.get(input, "rotationPeriod", 0)
    rotation_period > max_rotation_period
}

violation {
    in_scope
    not common.field_exists(input, "rotationPeriod")
}

# Decide outcomes
fail {
    violation
}

pass {
    in_scope
    not violation
}

skip {
    not in_scope
}

# Error message with evidence
kms_key_rotation_err = message {
    fail
} else = "GCP KMS encryption key rotates within 90 days" {
    pass
} else = "Resource not applicable or does not exist" {
    skip
}

# Evidence for debugging
evidence := {
    "name": common.get(input, "name", ""),
    "purpose": common.get(input, "purpose", ""),
    "rotationPeriod": common.get(input, "rotationPeriod", "not set"),
    "max_allowed": max_rotation_period,
    "violation": violation
}

# Legacy compatibility - map to old rule name
kms_key_rotation = true {
    pass
}

kms_key_rotation = false {
    fail
}

kms_key_rotation_metadata := {
    "Policy Code": "PR-GCP-CLD-KMS-001",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP KMS encryption key rotating in every 90 days",
    "Policy Description": "This policy identifies GCP KMS encryption keys that are not rotating every 90 days. A key is used to protect some corpus of data. A collection of files could be encrypted with the same key and people with decrypt permissions on that key would be able to decrypt those files. It's recommended to make sure the 'rotation period' is set to a specific time to ensure data cannot be accessed through the old key.",
    "Resource Type": "cloudkms.projects.locations.keyRings.cryptoKeys",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys"
}
