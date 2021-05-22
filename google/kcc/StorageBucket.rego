package rule

# https://cloud.google.com/config-connector/docs/reference/resource-docs/storage/storagebucket

#
# BUCKET_CMEK_DISABLED
#

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
#

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
