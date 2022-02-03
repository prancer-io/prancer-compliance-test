package rule

# https://cloud.google.com/storage/docs/json_api/v1/buckets

#
# PR-GCP-GDF-BKT-001
#

default storage_encrypt = null

gc_attribute_absence["storage_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.encryption.defaultKmsKeyName
}

source_path[{"storage_encrypt": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.encryption.defaultKmsKeyName
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption", "defaultKmsKeyName"]
        ],
    }
}

gc_issue["storage_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    count(resource.properties.encryption.defaultKmsKeyName) == 0
}

source_path[{"storage_encrypt": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    count(resource.properties.encryption.defaultKmsKeyName) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption", "defaultKmsKeyName"]
        ],
    }
}

storage_encrypt {
    lower(input.resources[i].type) == "storage.v1.bucket"
    not gc_issue["storage_encrypt"]
    not gc_attribute_absence["storage_encrypt"]
}

storage_encrypt = false {
    gc_issue["storage_encrypt"]
}

storage_encrypt = false {
    gc_attribute_absence["storage_encrypt"]
}

storage_encrypt_err = "GCP Storage bucket encrypted using default KMS key instead of a customer-managed key" {
    gc_issue["storage_encrypt"]
}

storage_encrypt_miss_err = "GCP Storage bucket attribute encryption missing in the resource" {
    gc_attribute_absence["storage_encrypt"]
}

storage_encrypt_metadata := {
    "Policy Code": "PR-GCP-GDF-BKT-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Storage bucket encrypted using default KMS key instead of a customer-managed key",
    "Policy Description": "This policy identifies Storage buckets that are encrypted with the default Google-managed keys. As a best practice, use Customer-managed key to encrypt the data in your storage bucket and ensure full control over your data.",
    "Resource Type": "storage.v1.bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}

#
# PR-GCP-GDF-BKT-002
#

default storage_versioning = null

gc_attribute_absence["storage_versioning"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.versioning
}

source_path[{"storage_versioning": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.versioning
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "versioning"]
        ],
    }
}

gc_issue["storage_versioning"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    contains(lower(resource.properties.acl[j].email), "logging")
    not resource.properties.versioning.enabled
}

source_path[{"storage_versioning": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    contains(lower(resource.properties.acl[j].email), "logging")
    not resource.properties.versioning.enabled
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "versioning", "enabled"]
        ],
    }
}

storage_versioning {
    lower(input.resources[i].type) == "storage.v1.bucket"
    not gc_issue["storage_versioning"]
    not gc_attribute_absence["storage_versioning"]
}

storage_versioning = false {
    gc_issue["storage_versioning"]
}

storage_versioning = false {
    gc_attribute_absence["storage_versioning"]
}

storage_versioning_err = "GCP Storage log buckets have object versioning disabled" {
    gc_issue["storage_versioning"]
}

storage_versioning_miss_err = "GCP Storage attribute versioning missing in the resource" {
    gc_attribute_absence["storage_versioning"]
}

storage_versioning_metadata := {
    "Policy Code": "PR-GCP-GDF-BKT-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Storage log buckets have object versioning disabled",
    "Policy Description": "This policy identifies Storage log buckets which have object versioning disabled. Enabling object versioning on storage log buckets will protect your cloud storage data from being overwritten or accidentally deleted. It is recommended to enable object versioning feature on all storage buckets where sinks are configured.",
    "Resource Type": "storage.v1.bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}

#
# PR-GCP-GDF-BKT-003
#

default storage_stack_logging = null

gc_attribute_absence["storage_stack_logging"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.logging
}

source_path[{"storage_stack_logging": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.logging
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logging"]
        ],
    }
}

gc_issue["storage_stack_logging"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    contains(lower(resource.properties.acl[j].email), "logging")
    not resource.properties.logging
}

source_path[{"storage_stack_logging": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    contains(lower(resource.properties.acl[j].email), "logging")
    not resource.properties.logging
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logging"]
        ],
    }
}

storage_stack_logging {
    lower(input.resources[i].type) == "storage.v1.bucket"
    not gc_issue["storage_stack_logging"]
    not gc_attribute_absence["storage_stack_logging"]
}

storage_stack_logging = false {
    gc_issue["storage_stack_logging"]
}

storage_stack_logging = false {
    gc_attribute_absence["storage_stack_logging"]
}

storage_stack_logging_err = "Logging on the Stackdriver exported Bucket is disabled" {
    gc_issue["storage_stack_logging"]
}

storage_stack_logging_miss_err = "GCP Storage attribute logging missing in the resource" {
    gc_attribute_absence["storage_stack_logging"]
}

storage_stack_logging_metadata := {
    "Policy Code": "PR-GCP-GDF-BKT-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Logging on the Stackdriver exported Bucket is disabled",
    "Policy Description": "Checks to ensure that logging is enabled on a Stackdriver exported Bucket. Enabled logging provides information about all the requests made on the bucket.",
    "Resource Type": "storage.v1.bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}

#
# PR-GCP-GDF-BKT-004
#

default storage_logging = null

gc_issue["storage_logging"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.logging.logBucket
}

source_path[{"storage_logging": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.logging.logBucket
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logging", "logBucket"]
        ],
    }
}

storage_logging {
    lower(input.resources[i].type) == "storage.v1.bucket"
    not gc_issue["storage_logging"]
}

storage_logging = false {
    gc_issue["storage_logging"]
}

storage_logging_err = "Storage Bucket does not have Access and Storage Logging enabled" {
    gc_issue["storage_logging"]
}

storage_logging_metadata := {
    "Policy Code": "PR-GCP-GDF-BKT-004",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Storage Bucket does not have Access and Storage Logging enabled",
    "Policy Description": "Checks to verify that the configuration on the Storage Buckets is enabled for access logs and storage logs.",
    "Resource Type": "storage.v1.bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}

#
# PR-GCP-GDF-BKT-005
#

default storage_public_logs = null

gc_attribute_absence["storage_public_logs"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.acl
}

source_path[{"storage_public_logs": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.acl
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "acl"]
        ],
    }
}

gc_issue["storage_public_logs"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    acl := resource.properties.acl[j]
    contains(lower(acl.email), "logging")
    contains(lower(acl.entity), "allusers")
}

source_path[{"storage_public_logs": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    acl := resource.properties.acl[j]
    contains(lower(acl.email), "logging")
    contains(lower(acl.entity), "allusers")
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "acl", j, "entity"]
        ],
    }
}

gc_issue["storage_public_logs"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    acl := resource.properties.acl[j]
    contains(lower(acl.email), "logging")
    contains(lower(acl.entity), "allauthenticatedusers")
}

source_path[{"storage_public_logs": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    acl := resource.properties.acl[j]
    contains(lower(acl.email), "logging")
    contains(lower(acl.entity), "allauthenticatedusers")
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "acl", j, "entity"]
        ],
    }
}

storage_public_logs {
    lower(input.resources[i].type) == "storage.v1.bucket"
    not gc_issue["storage_public_logs"]
    not gc_attribute_absence["storage_public_logs"]
}

storage_public_logs = false {
    gc_issue["storage_public_logs"]
}

storage_public_logs = false {
    gc_attribute_absence["storage_public_logs"]
}

storage_public_logs_err = "Storage Buckets with publicly accessible Stackdriver logs" {
    gc_issue["storage_public_logs"]
}

storage_public_logs_miss_err = "GCP Storage attribute acl missing in the resource" {
    gc_attribute_absence["storage_public_logs"]
}

storage_public_logs_metadata := {
    "Policy Code": "PR-GCP-GDF-BKT-005",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Storage Buckets with publicly accessible Stackdriver logs",
    "Policy Description": "Checks to ensure that Stackdriver logs on Storage Buckets are not public. Giving public access to Stackdriver logs will enable anyone with a web association to retrieve sensitive information that is critical to business. Stackdriver Logging enables to store, search, investigate, monitor and alert on log information/events from Google Cloud Platform. The permission needs to be set only for authorized users.",
    "Resource Type": "storage.v1.bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}


#
# PR-GCP-GDF-BKT-006
#

default storage_uniform_bucket_access = null

gc_attribute_absence["storage_uniform_bucket_access"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.iamConfiguration
}

gc_attribute_absence["storage_uniform_bucket_access"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.iamConfiguration.uniformBucketLevelAccess.enabled
}

storage_uniform_bucket_access {
    lower(input.resources[i].type) == "storage.v1.bucket"
    not gc_issue["storage_uniform_bucket_access"]
    not gc_attribute_absence["storage_uniform_bucket_access"]
}

storage_uniform_bucket_access = false {
    gc_issue["storage_uniform_bucket_access"]
}

storage_uniform_bucket_access = false {
    gc_attribute_absence["storage_uniform_bucket_access"]
}

storage_uniform_bucket_access_err = "GCP cloud storage bucket with uniform bucket-level access disabled" {
    gc_issue["storage_uniform_bucket_access"]
} else = "GCP cloud storage bucket `iamConfiguration.uniformBucketLevelAccess.enabled` property is missing" {
    gc_attribute_absence["storage_uniform_bucket_access"]
}

storage_uniform_bucket_access_metadata := {
    "Policy Code": "PR-GCP-GDF-BKT-006",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure cloud storage bucket with uniform bucket-level access enabled",
    "Policy Description": "Checks to ensure that Stackdriver logs on Storage Buckets are not public. Giving public access to Stackdriver logs will enable anyone with a web association to retrieve sensitive information that is critical to business. Stackdriver Logging enables to store, search, investigate, monitor and alert on log information/events from Google Cloud Platform. The permission needs to be set only for authorized users.",
    "Resource Type": "storage.v1.bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}


#
# PR-GCP-GDF-BKT-007
#

default storage_event_based_hold = null

gc_attribute_absence["storage_event_based_hold"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.defaultEventBasedHold
}

gc_issue["storage_event_based_hold"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    resource.properties.defaultEventBasedHold == false   
}

storage_event_based_hold {
    lower(input.resources[i].type) == "storage.v1.bucket"
    not gc_issue["storage_event_based_hold"]
    not gc_attribute_absence["storage_event_based_hold"]
}

storage_event_based_hold = false {
    gc_issue["storage_event_based_hold"]
}

storage_event_based_hold = false {
    gc_attribute_absence["storage_event_based_hold"]
}

storage_event_based_hold_err = "GCP cloud storage bucket is not configured with default Event-Based hold" {
    gc_issue["storage_event_based_hold"]
} else = "GCP cloud storage bucket `defaultEventBasedHold` property is missing" {
    gc_attribute_absence["storage_event_based_hold"]
}

storage_event_based_hold_metadata := {
    "Policy Code": "PR-GCP-GDF-BKT-007",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP storage bucket is configured with default Event-Based hold",
    "Policy Description": "This policy identifies GCP storage buckets that are not configured with default Event-Based Hold. An event-based hold resets the object's time in the bucket for the purposes of the retention period. This behavior is useful when you want an object to persist in your bucket for a certain length of time after a certain event occurs. It is recommended to enable this feature to protect individual objects from deletion.",
    "Resource Type": "storage.v1.bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}


#
# PR-GCP-GDF-BKT-008
#

default storage_logging_itself = null

gc_attribute_absence["storage_logging_itself"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.logging.logBucket
}

gc_issue["storage_logging_itself"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    resource.properties.logging.logBucket == resource.name
}

storage_logging_itself {
    lower(input.resources[i].type) == "storage.v1.bucket"
    not gc_issue["storage_logging_itself"]
    not gc_attribute_absence["storage_logging_itself"]
}

storage_logging_itself = false {
    gc_issue["storage_logging_itself"]
}

storage_logging_itself = false {
    gc_attribute_absence["storage_logging_itself"]
}

storage_logging_itself_err = "GCP cloud storage bucket is logging to itself" {
    gc_issue["storage_logging_itself"]
} else = "GCP cloud storage bucket `logging.logBucket` property is missing" {
    gc_attribute_absence["storage_logging_itself"]
}

storage_logging_itself_metadata := {
    "Policy Code": "PR-GCP-GDF-BKT-008",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP storage bucket is not logging to itself",
    "Policy Description": "This policy identifies GCP storage buckets that are sending logs to themselves. When storage buckets use the same bucket to send their access logs, a loop of logs will be created, which is not a security best practice. It is recommended to spin up new and different log buckets for storage bucket logging.",
    "Resource Type": "storage.v1.bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}



#
# PR-GCP-GDF-BKT-009
#

default storage_bucket_lock = null

gc_issue["storage_bucket_lock"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.retentionPolicy.isLocked
}

gc_issue["storage_bucket_lock"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    lower(resource.properties.retentionPolicy.isLocked) == "false"
}

storage_bucket_lock {
    lower(input.resources[i].type) == "storage.v1.bucket"
    not gc_issue["storage_bucket_lock"]
}

storage_bucket_lock = false {
    gc_issue["storage_bucket_lock"]
}

storage_bucket_lock_err = "Ensure GCP Log bucket retention policy is configured using bucket lock" {
    gc_issue["storage_bucket_lock"]
}

storage_bucket_lock_metadata := {
    "Policy Code": "PR-GCP-GDF-BKT-009",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP Log bucket retention policy is configured using bucket lock",
    "Policy Description": "This policy identifies GCP log buckets for which retention policy is not configured using bucket lock. It is recommended to configure the data retention policy for cloud storage buckets using bucket lock to permanently prevent the policy from being reduced or removed in case the system is compromised by an attacker or a malicious insider.\n\nNote: Locking a bucket is an irreversible action. Once you lock a bucket, you cannot remove the retention policy from the bucket or decrease the retention period for the policy.",
    "Resource Type": "storage.v1.bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}



#
# PR-GCP-GDF-BKT-010
#

default storage_bucket_retention_enable = null

gc_issue["storage_bucket_retention_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.retentionPolicy
}

gc_issue["storage_bucket_retention_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    resource.properties.retentionPolicy == null
}

gc_issue["storage_bucket_retention_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    count(resource.properties.retentionPolicy) == 0
}


storage_bucket_retention_enable {
    lower(input.resources[i].type) == "storage.v1.bucket"
    not gc_issue["storage_bucket_retention_enable"]
}

storage_bucket_retention_enable = false {
    gc_issue["storage_bucket_retention_enable"]
}

storage_bucket_retention_enable_err = "Ensure GCP Log bucket retention policy is enabled" {
    gc_issue["storage_bucket_retention_enable"]
}

storage_bucket_retention_enable_metadata := {
    "Policy Code": "PR-GCP-GDF-BKT-010",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP Log bucket retention policy is enabled",
    "Policy Description": "This policy identifies GCP log buckets for which retention policy is not enabled. Enabling retention policies on log buckets will protect logs stored in cloud storage buckets from being overwritten or accidentally deleted. It is recommended to configure a data retention policy for these cloud storage buckets to store the activity logs for forensics and security investigations.",
    "Resource Type": "storage.v1.bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}

