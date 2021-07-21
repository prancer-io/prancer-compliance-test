package rule

# https://cloud.google.com/storage/docs/json_api/v1/buckets

#
# PR-GCP-0063-TRF
#

default storage_encrypt = null

gc_attribute_absence["storage_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket"
    resource.properties.encryption != null
    not resource.properties.encryption[_].default_kms_key_name
}

gc_issue["storage_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket"
    resource.properties.encryption != null
    count(resource.properties.encryption[_].default_kms_key_name) == 0
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
    "Policy Code": "PR-GCP-0063-TRF",
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
# PR-GCP-0066-TRF
#

default storage_versioning = null

gc_attribute_absence["storage_versioning"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket"
    not resource.properties.versioning
}

gc_issue["storage_versioning"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket"
    resource.properties.versioning != null
    resource.properties.versioning[_].enabled != true
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
    "Policy Code": "PR-GCP-0066-TRF",
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
# PR-GCP-0089-TRF
#

default storage_logging = null

gc_issue["storage_logging"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket"
    resource.properties.logging != null
    not resource.properties.logging[_].log_bucket
}

storage_logging {
    lower(input.resources[_].type) == "google_storage_bucket"
    not gc_issue["storage_logging"]
}

storage_logging = false {
    gc_issue["storage_logging"]
}

storage_logging_err = "Storage Bucket does not have Access and Storage Logging enabled" {
    gc_issue["storage_logging"]
}

storage_logging_metadata := {
    "Policy Code": "PR-GCP-0089-TRF",
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
# PR-GCP-0090-TRF
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
    "Policy Code": "PR-GCP-0090-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Storage Buckets with publicly accessible Stackdriver logs",
    "Policy Description": "Checks to ensure that Stackdriver logs on Storage Buckets are not public. Giving public access to Stackdriver logs will enable anyone with a web association to retrieve sensitive information that is critical to business. Stackdriver Logging enables to store, search, investigate, monitor and alert on log information/events from Google Cloud Platform. The permission needs to be set only for authorized users.",
    "Resource Type": "google_storage_bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
}
