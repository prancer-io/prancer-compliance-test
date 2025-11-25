package rule

#
# PR-GCP-CLD-SCR-001
#

default secret_rotation_enabled = null

gc_issue["secret_rotation_enabled"] {
    not input.rotation.rotationPeriod
}

gc_issue["secret_rotation_enabled"] {
    input.rotation.rotationPeriod == ""
}

gc_issue["secret_rotation_enabled"] {
    input.rotation.rotationPeriod == null
}

secret_rotation_enabled {
    not gc_issue["secret_rotation_enabled"]
}

secret_rotation_enabled = false {
    gc_issue["secret_rotation_enabled"]
}

secret_rotation_enabled_err = "Ensure GCP secret manager value rotation should be enabled" {
    gc_issue["secret_rotation_enabled"]
}

secret_rotation_enabled_metadata := {
    "Policy Code": "PR-GCP-CLD-SCR-001",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP secret manager rotation should be enabled",
    "Policy Description": "This policy identifies GCP secrets that are not rotated. A  Secret Manager is used to securely store API keys, passwords, and other sensitive information. It is recommended to make sure the 'rotation period' is set to a specific time to ensure data cannot be accessed through the old value.",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets"
}

#
# PR-GCP-CLD-SCR-002
#

default secret_rotation = null

gc_issue["secret_rotation_90_days"] {
    not input.rotation
}

gc_issue["secret_rotation_90_days"] {
    not input.rotation.rotationPeriod
}

gc_issue["secret_rotation_90_days"] {
    rotationPeriod := trim_right(input.rotation.rotationPeriod, "s")
    to_number(rotationPeriod) > 7776000
}

secret_rotation {
    not gc_issue["secret_rotation_90_days"]
}

secret_rotation = false {
    gc_issue["secret_rotation_90_days"]
}

secret_rotation_err = "Ensure GCP secret manager value rotating in every 90 days" {
    gc_issue["secret_rotation_90_days"]
}

secret_rotation_metadata := {
    "Policy Code": "PR-GCP-CLD-SCR-002",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure that the GCP Secret Manager is rotated every 90 days or less",
    "Policy Description": "This policy identifies GCP secrets that are not rotated with in every 90 days. A  Secret Manager is used to securely store API keys, passwords, and other sensitive information. It is recommended to make sure the 'rotation period' is set to a specific time to ensure data cannot be accessed through the old value.",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets"
}


#
# PR-GCP-CLD-SCR-003
#

default secret_customer_managed_encryption = null

gc_issue["secret_customer_managed_encryption_not_enabled"] {
    not input.replication.automatic.customerManagedEncryption
}

gc_issue["secret_customer_managed_encryption_not_enabled"] {
    input.replication.automatic.customerManagedEncryption.kmsKeyName == ""
}

gc_issue["secret_customer_managed_encryption_not_enabled"] {
    input.replication.automatic.customerManagedEncryption.kmsKeyName == null
}

secret_customer_managed_encryption {
    not gc_issue["secret_customer_managed_encryption_not_enabled"]
}

secret_customer_managed_encryption = false {
    gc_issue["secret_customer_managed_encryption_not_enabled"]
}

secret_customer_managed_encryption_err = "Ensure GCP secrets should be encrypted with a customer-managed key" {
    gc_issue["secret_customer_managed_encryption_not_enabled"]
}

secret_customer_managed_encryption_metadata := {
    "Policy Code": "PR-GCP-CLD-SCR-003",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP secrets should be encrypted with a customer-managed key",
    "Policy Description": "This policy identifies GCP secrets that are not encrypted with a customer-managed key. By default secret payloads are encrypted by keys managed by Google. It is recommended to make sure the secrets are encrypted with the Customer managed keys for greater control.",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets"
}

#
# PR-GCP-CLD-SCR-004
#

default secret_iam_over_privilged = null

gc_issue["secret_iam_over_privilged_not_enabled"] {
    binding := input.bindings[_]
    contains(lower(binding.members[_]), "allauthenticatedusers")
}

gc_issue["secret_iam_over_privilged_not_enabled"] {
    binding := input.bindings[_]
    contains(lower(binding.members[_]), "allusers")
}

secret_iam_over_privilged {
    not gc_issue["secret_iam_over_privilged_not_enabled"]
}

secret_iam_over_privilged = false {
    gc_issue["secret_iam_over_privilged_not_enabled"]
}

secret_iam_over_privilged_err = "Ensure GCP secrets should be encrypted with a customer-managed key" {
    gc_issue["secret_iam_over_privilged_not_enabled"]
}

secret_iam_over_privilged_metadata := {
    "Policy Code": "PR-GCP-CLD-SCR-004",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP secrets should not have over priviliged access",
    "Policy Description": "This policy identifies GCP secrets with overprivileged access. It is recommended to provide the minimum necessary access to resources to perform a specific task to comply with the principle of least privileges and to prevent possible privilege escalation.",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets"
}