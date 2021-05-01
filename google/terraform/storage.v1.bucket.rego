package rule

# https://cloud.google.com/storage/docs/json_api/v1/buckets

#
# PR-GCP-0063-TRF
#

default storage_encrypt = null

gc_attribute_absence["storage_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket"
    not resource.properties.encryption.default_kms_key_name
}

gc_issue["storage_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket"
    count(resource.properties.encryption.default_kms_key_name) == 0
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
    resource.properties.versioning.enabled != true
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

#
# PR-GCP-0089-TRF
#

default storage_logging = null

gc_issue["storage_logging"] {
    resource := input.resources[_]
    lower(resource.type) == "google_storage_bucket"
    not resource.properties.logging.log_bucket
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
