package rule

# https://cloud.google.com/config-connector/docs/reference/resource-docs/storage/storagebucket

#
# BUCKET_CMEK_DISABLED
# PR-GCP-0059-KCC

default bucket_cmek_disabled = null


gc_issue["bucket_cmek_disabled"] {
    lower(input.kind) == "storagebucket"
    not input.spec.encryption.kmsKeyRef
}

bucket_cmek_disabled {
    lower(input.kind) == "storagebucket"
    not gc_issue["bucket_cmek_disabled"]
}

bucket_cmek_disabled = false {
    gc_issue["bucket_cmek_disabled"]
}

bucket_cmek_disabled_err = "A bucket is not encrypted with customer-managed encryption keys (CMEK)." {
    gc_issue["bucket_cmek_disabled"]
}

bucket_cmek_disabled_metadata := {
    "Policy Code": "BUCKET_CMEK_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Bucket CMEK Disabled",
    "Policy Description": "A bucket is not encrypted with customer-managed encryption keys (CMEK).",
    "Resource Type": "StorageBucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/storage/storagebucket"
}

#
# BUCKET_POLICY_ONLY_DISABLED
# PR-GCP-0060-KCC

default bucket_policy_only_disabled = null

gc_issue["bucket_policy_only_disabled"] {
    lower(input.kind) == "storagebucket"
    not input.spec.uniformBucketLevelAccess
}

bucket_policy_only_disabled {
    lower(input.kind) == "storagebucket"
    not gc_issue["bucket_policy_only_disabled"]
}

bucket_policy_only_disabled = false {
    gc_issue["bucket_policy_only_disabled"]
}

bucket_policy_only_disabled_err = "Uniform bucket-level access, previously called Bucket Policy Only, isn't configured." {
    gc_issue["bucket_policy_only_disabled"]
}

bucket_policy_only_disabled_metadata := {
    "Policy Code": "BUCKET_POLICY_ONLY_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Bucket Policy Only Disabled",
    "Policy Description": "Uniform bucket-level access, previously called Bucket Policy Only, isn't configured.",
    "Resource Type": "StorageBucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/storage/storagebucket"
}

#
# BUCKET_LOGGING_DISABLED
# PR-GCP-0061-KCC

default bucket_logging_disabled = null

gc_issue["bucket_logging_disabled"] {
    lower(input.kind) == "storagebucket"
    not input.spec.logging.logBucket
}

bucket_logging_disabled {
    lower(input.kind) == "storagebucket"
    not gc_issue["bucket_logging_disabled"]
}

bucket_logging_disabled = false {
    gc_issue["bucket_logging_disabled"]
}

bucket_logging_disabled_err = "There is a storage bucket without logging enabled." {
    gc_issue["bucket_logging_disabled"]
}

bucket_logging_disabled_metadata := {
    "Policy Code": "BUCKET_LOGGING_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Bucket Logging Disabled",
    "Policy Description": "There is a storage bucket without logging enabled.",
    "Resource Type": "StorageBucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/storage/storagebucket"
}

#
# LOCKED_RETENTION_POLICY_NOT_SET
# PR-GCP-0062-KCC

default locked_retention_policy_not_set = null

gc_issue["locked_retention_policy_not_set"] {
    lower(input.kind) == "storagebucket"
    not input.spec.retentionPolicy.isLocked
}

locked_retention_policy_not_set {
    lower(input.kind) == "storagebucket"
    not gc_issue["locked_retention_policy_not_set"]
}

locked_retention_policy_not_set = false {
    gc_issue["locked_retention_policy_not_set"]
}

locked_retention_policy_not_set_err = "A locked retention policy is not set for logs." {
    gc_issue["locked_retention_policy_not_set"]
}

locked_retention_policy_not_set_metadata := {
    "Policy Code": "LOCKED_RETENTION_POLICY_NOT_SET",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Locked Retention Policy Not Set",
    "Policy Description": "A locked retention policy is not set for logs.",
    "Resource Type": "StorageBucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/storage/storagebucket"
}

#
# OBJECT_VERSIONING_DISABLED
# PR-GCP-0063-KCC

default object_versioning_disabled = null

gc_issue["object_versioning_disabled"] {
    lower(input.kind) == "storagebucket"
    not input.spec.versioning.enabled
}

object_versioning_disabled {
    lower(input.kind) == "storagebucket"
    not gc_issue["object_versioning_disabled"]
}

object_versioning_disabled = false {
    gc_issue["object_versioning_disabled"]
}

object_versioning_disabled_err = "Object versioning isn't enabled on a storage bucket where sinks are configured." {
    gc_issue["object_versioning_disabled"]
}

object_versioning_disabled_metadata := {
    "Policy Code": "OBJECT_VERSIONING_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Object Versioning Disabled",
    "Policy Description": "Object versioning isn't enabled on a storage bucket where sinks are configured.",
    "Resource Type": "StorageBucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/storage/storagebucket"
}
