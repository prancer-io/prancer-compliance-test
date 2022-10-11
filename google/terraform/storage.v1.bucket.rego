package rule

concat_string(value1, value2) = output {
    out := array.concat([value1], [value2])
    x := concat("", out)
    output := x
}

# https://cloud.google.com/storage/docs/json_api/v1/buckets

#
# PR-GCP-TRF-BKT-001
#

default storage_encrypt = null

gc_attribute_absence["storage_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket"
    not resource.properties.encryption
}

gc_attribute_absence["storage_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket"
    count(resource.properties.encryption) = 0
}

gc_issue["storage_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket"
    encryption := resource.properties.encryption[_]
    count(encryption.default_kms_key_name) == 0
}

storage_encrypt {
    lower(input.resources[_].type) == "google_storage_bucket"
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
    "Policy Code": "PR-GCP-TRF-BKT-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Storage bucket encrypted using default KMS key instead of a customer-managed key",
    "Policy Description": "This policy identifies Storage buckets that are encrypted with the default Google-managed keys. As a best practice, use Customer-managed key to encrypt the data in your storage bucket and ensure full control over your data.",
    "Resource Type": "google_storage_bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}

#
# PR-GCP-TRF-BKT-002
#

default storage_versioning = null

gc_attribute_absence["storage_versioning"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket"
    not resource.properties.versioning
}

gc_attribute_absence["storage_versioning"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket"
    count(resource.properties.versioning) == 0
}

gc_issue["storage_versioning"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket"
    versioning := resource.properties.versioning[_]
    versioning.enabled != true
}

storage_versioning {
    lower(input.resources[_].type) == "google_storage_bucket"
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
    "Policy Code": "PR-GCP-TRF-BKT-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Storage log buckets have object versioning disabled",
    "Policy Description": "This policy identifies Storage log buckets which have object versioning disabled. Enabling object versioning on storage log buckets will protect your cloud storage data from being overwritten or accidentally deleted. It is recommended to enable object versioning feature on all storage buckets where sinks are configured.",
    "Resource Type": "google_storage_bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}


#
# PR-GCP-TRF-BKT-003
#

default storage_stack_logging = null

gc_issue["storage_stack_logging"] {
    resource := input.resources[i]
    lower(resource.type) == "google_storage_bucket"
    not resource.properties.logging
}

storage_stack_logging {
    lower(input.resources[i].type) == "google_storage_bucket"
    not gc_issue["storage_stack_logging"]
}

storage_stack_logging = false {
    gc_issue["storage_stack_logging"]
}

storage_stack_logging_err = "Logging on the Stackdriver exported Bucket is disabled" {
    gc_issue["storage_stack_logging"]
}

storage_stack_logging_metadata := {
    "Policy Code": "PR-GCP-TRF-BKT-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "terraform",
    "Policy Title": "Logging on the Stackdriver exported Bucket is disabled",
    "Policy Description": "Checks to ensure that logging is enabled on a Stackdriver exported Bucket. Enabled logging provides information about all the requests made on the bucket.",
    "Resource Type": "google_storage_bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}


#
# PR-GCP-TRF-BKT-004
#

default storage_logging = null

gc_attribute_absence["storage_logging"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket"
    not resource.properties.logging
}

gc_attribute_absence["storage_logging"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket"
    count(resource.properties.logging) == 0
}

gc_issue["storage_logging"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket"
    logging := resource.properties.logging[_]
    not logging.log_bucket
}

storage_logging {
    lower(input.resources[_].type) == "google_storage_bucket"
    not gc_issue["storage_logging"]
    not gc_attribute_absence["storage_logging"]
}

storage_logging = false {
    gc_issue["storage_logging"]
}

storage_logging = false {
    gc_attribute_absence["storage_logging"]
}

storage_logging_err = "Storage Bucket does not have Access and Storage Logging enabled" {
    gc_issue["storage_stack_logging"]
} else = "Storage Bucket does not have Access and Storage Logging enabled" {
    gc_attribute_absence["storage_logging"]
}

storage_logging_metadata := {
    "Policy Code": "PR-GCP-TRF-BKT-004",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Storage Bucket does not have Access and Storage Logging enabled",
    "Policy Description": "Checks to verify that the configuration on the Storage Buckets is enabled for access logs and storage logs.",
    "Resource Type": "google_storage_bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}

#
# PR-GCP-TRF-BKT-005
#

default storage_public_logs = null

gc_issue["storage_public_logs"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket_acl"
    acl := resource.properties.acl[_]
    contains(lower(acl.role_entity), "logging")
    contains(lower(acl.role_entity), "allusers")
}

gc_issue["storage_public_logs"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket_acl"
    acl := resource.properties.acl[_]
    contains(lower(acl.role_entity), "logging")
    contains(lower(acl.role_entity), "allauthenticatedusers")
}

storage_public_logs {
    lower(input.resources[_].type) == "google_storage_bucket_acl"
    not gc_issue["storage_public_logs"]
}

storage_public_logs = false {
    gc_issue["storage_public_logs"]
}

storage_public_logs_err = "Storage Buckets with publicly accessible Stackdriver logs" {
    gc_issue["storage_public_logs"]
}

storage_public_logs_metadata := {
    "Policy Code": "PR-GCP-TRF-BKT-005",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Storage Buckets with publicly accessible Stackdriver logs",
    "Policy Description": "Checks to ensure that Stackdriver logs on Storage Buckets are not public. Giving public access to Stackdriver logs will enable anyone with a web association to retrieve sensitive information that is critical to business. Stackdriver Logging enables to store, search, investigate, monitor and alert on log information/events from Google Cloud Platform. The permission needs to be set only for authorized users.",
    "Resource Type": "google_storage_bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}


#
# PR-GCP-TRF-BKT-006
#

default storage_uniform_bucket_access = null

gc_attribute_absence["storage_uniform_bucket_access"] {
    resource := input.resources[i]
    lower(resource.type) == "google_storage_bucket"
    not resource.properties.uniform_bucket_level_access
}

gc_issue["storage_uniform_bucket_access"] {
    resource := input.resources[i]
    lower(resource.type) == "google_storage_bucket"
    resource.properties.uniform_bucket_level_access == false   
}

storage_uniform_bucket_access {
    lower(input.resources[i].type) == "google_storage_bucket"
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
} else = "GCP cloud storage bucket `uniform_bucket_level_access` property is missing" {
    gc_attribute_absence["storage_uniform_bucket_access"]
}

storage_uniform_bucket_access_metadata := {
    "Policy Code": "PR-GCP-TRF-BKT-006",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure cloud storage bucket with uniform bucket-level access enabled",
    "Policy Description": "Checks to ensure that Stackdriver logs on Storage Buckets are not public. Giving public access to Stackdriver logs will enable anyone with a web association to retrieve sensitive information that is critical to business. Stackdriver Logging enables to store, search, investigate, monitor and alert on log information/events from Google Cloud Platform. The permission needs to be set only for authorized users.",
    "Resource Type": "google_storage_bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}



#
# PR-GCP-TRF-BKT-007
#

default storage_event_based_hold = null

gc_issue["storage_event_based_hold"] {
    resource := input.resources[i]
    lower(resource.type) == "google_storage_bucket"
    not resource.properties.default_event_based_hold
}

storage_event_based_hold {
    lower(input.resources[i].type) == "google_storage_bucket"
    not gc_issue["storage_event_based_hold"]
}

storage_event_based_hold = false {
    gc_issue["storage_event_based_hold"]
}


storage_event_based_hold_err = "GCP cloud storage bucket is not configured with default Event-Based hold" {
    gc_issue["storage_event_based_hold"]
}

storage_event_based_hold_metadata := {
    "Policy Code": "PR-GCP-TRF-BKT-007",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "terraform",
    "Policy Title": "Ensure GCP storage bucket is configured with default Event-Based hold",
    "Policy Description": "This policy identifies GCP storage buckets that are not configured with default Event-Based Hold. An event-based hold resets the object's time in the bucket for the purposes of the retention period. This behavior is useful when you want an object to persist in your bucket for a certain length of time after a certain event occurs. It is recommended to enable this feature to protect individual objects from deletion.",
    "Resource Type": "google_storage_bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}



#
# PR-GCP-TRF-BKT-008
#

default storage_logging_itself = null

gc_attribute_absence["storage_logging_itself"] {
    resource := input.resources[i]
    lower(resource.type) == "google_storage_bucket"
    not resource.properties.logging.log_bucket
}

gc_issue["storage_logging_itself"] {
    resource := input.resources[i]
    lower(resource.type) == "google_storage_bucket"
    contains(resource.properties.logging.log_bucket, concat_string("google_storage_bucket.", resource.name))
}

gc_issue["storage_logging_itself"] {
    resource := input.resources[i]
    lower(resource.type) == "google_storage_bucket"
    resource.properties.logging.log_bucket == resource.name
}

storage_logging_itself {
    lower(input.resources[i].type) == "google_storage_bucket"
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
} else = "GCP cloud storage bucket `logging.log_bucket` property is missing" {
    gc_attribute_absence["storage_logging_itself"]
}

storage_logging_itself_metadata := {
    "Policy Code": "PR-GCP-TRF-BKT-008",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP storage bucket is not logging to itself",
    "Policy Description": "This policy identifies GCP storage buckets that are sending logs to themselves. When storage buckets use the same bucket to send their access logs, a loop of logs will be created, which is not a security best practice. It is recommended to spin up new and different log buckets for storage bucket logging.",
    "Resource Type": "google_storage_bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}

#
# PR-GCP-TRF-BKT-009
#

default storage_bucket_lock = null

gc_attribute_absence["storage_bucket_lock"] {
    resource := input.resources[i]
    lower(resource.type) == "google_storage_bucket"
    not resource.properties.retention_policy.is_locked
}

gc_issue["storage_bucket_lock"] {
    resource := input.resources[i]
    lower(resource.type) == "google_storage_bucket"
    resource.properties.retention_policy.is_locked == false
}

storage_bucket_lock {
    lower(input.resources[i].type) == "google_storage_bucket"
    not gc_issue["storage_bucket_lock"]
    not gc_attribute_absence["storage_bucket_lock"]
}

storage_bucket_lock = false {
    gc_issue["storage_bucket_lock"]
}

storage_bucket_lock = false {
    gc_attribute_absence["storage_bucket_lock"]
}

storage_bucket_lock_err = "Ensure GCP Log bucket retention policy is configured using bucket lock" {
    gc_issue["storage_bucket_lock"]
} else = "GCP cloud storage bucket `retention_policy.is_locked` property is missing" {
    gc_attribute_absence["storage_bucket_lock"]
}

storage_bucket_lock_metadata := {
    "Policy Code": "PR-GCP-TRF-BKT-009",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Log bucket retention policy is configured using bucket lock",
    "Policy Description": "This policy identifies GCP log buckets for which retention policy is not configured using bucket lock. It is recommended to configure the data retention policy for cloud storage buckets using bucket lock to permanently prevent the policy from being reduced or removed in case the system is compromised by an attacker or a malicious insider.\n\nNote: Locking a bucket is an irreversible action. Once you lock a bucket, you cannot remove the retention policy from the bucket or decrease the retention period for the policy.",
    "Resource Type": "google_storage_bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}

#
# PR-GCP-TRF-BKT-010
#

default storage_bucket_retention_enable = null

gc_attribute_absence["storage_bucket_retention_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "google_storage_bucket"
    not resource.properties.retention_policy
}

gc_attribute_absence["storage_bucket_retention_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "google_storage_bucket"
    not resource.properties.retention_policy.retention_period
}

storage_bucket_retention_enable {
    lower(input.resources[i].type) == "google_storage_bucket"
    not gc_attribute_absence["storage_bucket_retention_enable"]
}

storage_bucket_retention_enable = false {
    gc_attribute_absence["storage_bucket_retention_enable"]
}

storage_bucket_retention_enable_err = "Ensure GCP Log bucket retention policy is enabled" {
    gc_attribute_absence["storage_bucket_retention_enable"]
}

storage_bucket_retention_enable_metadata := {
    "Policy Code": "PR-GCP-TRF-BKT-010",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Log bucket retention policy is enabled",
    "Policy Description": "This policy identifies GCP log buckets for which retention policy is not enabled. Enabling retention policies on log buckets will protect logs stored in cloud storage buckets from being overwritten or accidentally deleted. It is recommended to configure a data retention policy for these cloud storage buckets to store the activity logs for forensics and security investigations.",
    "Resource Type": "google_storage_bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}


#
# PR-GCP-TRF-BKT-011
#
google_storage_bucket_iam = ["google_storage_bucket_iam_policy", "google_storage_bucket_iam_binding", "google_storage_bucket_iam_member"]

default publicly_to_all_authenticated_users = null

gc_issue["publicly_to_all_authenticated_users"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket_iam_policy"
    bindings := resource.properties.binding[_]
    contains(lower(bindings.role), "roles/storage")
    contains(lower(bindings.members[_]), "allauthenticatedusers")
}

gc_issue["publicly_to_all_authenticated_users"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket_iam_policy"
    bindings := resource.properties.binding[_]
    contains(lower(bindings.role), "roles/storage")
    contains(lower(bindings.member[_]), "allauthenticatedusers")
}

gc_issue["publicly_to_all_authenticated_users"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket_iam_binding"
    bindings := resource.properties
    contains(lower(bindings.role), "roles/storage")
    contains(lower(bindings.members[_]), "allauthenticatedusers")
}

gc_issue["publicly_to_all_authenticated_users"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket_iam_binding"
    bindings := resource.properties
    contains(lower(bindings.role), "roles/storage")
    contains(lower(bindings.member[_]), "allauthenticatedusers")
}

gc_issue["publicly_to_all_authenticated_users"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket_iam_member"
    bindings := resource.properties
    contains(lower(bindings.role), "roles/storage")
    contains(lower(bindings.members), "allauthenticatedusers")
}

gc_issue["publicly_to_all_authenticated_users"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket_iam_member"
    bindings := resource.properties
    contains(lower(bindings.role), "roles/storage")
    contains(lower(bindings.member), "allauthenticatedusers")
}

publicly_to_all_authenticated_users {
    lower(input.resources[_].type) == google_storage_bucket_iam[_]
    not gc_issue["publicly_to_all_authenticated_users"]
}

publicly_to_all_authenticated_users = false {
    gc_issue["publicly_to_all_authenticated_users"]
}

publicly_to_all_authenticated_users_err = "Ensure GCP Storage buckets are publicly accessible to all authenticated users." {
    gc_issue["publicly_to_all_authenticated_users"]
}

publicly_to_all_authenticated_users_metadata := {
    "Policy Code": "PR-GCP-TRF-BKT-011",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Storage buckets are publicly accessible to all authenticated users.",
    "Policy Description": "Checks the buckets which are publicly accessible to all authenticated users. Enabling public access to Storage Buckets enables anybody with a web association to access sensitive information that is critical to business. Access over a whole bucket is controlled by IAM. Access to individual objects within the bucket is controlled by its ACLs.",
    "Resource Type": ["google_storage_bucket_iam_policy", "google_storage_bucket_iam_member", "google_storage_bucket_iam_binding"]
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}


#
# PR-GCP-TRF-BKT-012
#

default publicly_to_all_users = null

gc_issue["publicly_to_all_users"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket_iam_policy"
    bindings := resource.properties.binding[_]
    contains(lower(bindings.role), "roles/storage")
    contains(lower(bindings.members[_]), "alluser")
}

gc_issue["publicly_to_all_users"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket_iam_policy"
    bindings := resource.properties.binding[_]
    contains(lower(bindings.role), "roles/storage")
    contains(lower(bindings.member[_]), "alluser")
}

gc_issue["publicly_to_all_users"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket_iam_binding"
    bindings := resource.properties
    contains(lower(bindings.role), "roles/storage")
    contains(lower(bindings.members[_]), "alluser")
}

gc_issue["publicly_to_all_users"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket_iam_binding"
    bindings := resource.properties
    contains(lower(bindings.role), "roles/storage")
    contains(lower(bindings.member[_]), "alluser")
}

gc_issue["publicly_to_all_users"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket_iam_member"
    bindings := resource.properties
    contains(lower(bindings.role), "roles/storage")
    contains(lower(bindings.members), "alluser")
}

gc_issue["publicly_to_all_users"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket_iam_member"
    bindings := resource.properties
    contains(lower(bindings.role), "roles/storage")
    contains(lower(bindings.member), "alluser")
}

publicly_to_all_users {
    lower(input.resources[_].type) == google_storage_bucket_iam[_]
    not gc_issue["publicly_to_all_users"]
}

publicly_to_all_users = false {
    gc_issue["publicly_to_all_users"]
}

publicly_to_all_users_err = "Ensure GCP Storage buckets are publicly accessible to all users." {
    gc_issue["publicly_to_all_users"]
}

publicly_to_all_users_metadata := {
    "Policy Code": "PR-GCP-TRF-BKT-012",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Storage buckets are publicly accessible to all users.",
    "Policy Description": "Checks the buckets which are publicly accessible to all users. Enabling public access to Storage buckets enables anybody with a web association to access sensitive information that is critical to business. Access over a whole bucket is controlled by IAM. Access to individual objects within the bucket is controlled by its ACLs.",
    "Resource Type": ["google_storage_bucket_iam_policy", "google_storage_bucket_iam_member", "google_storage_bucket_iam_binding"]
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}