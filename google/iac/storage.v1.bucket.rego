package rule

# https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances

#
# Id: 333
#

default storage_encrypt = null

gc_attribute_absence["storage_encrypt"] {
    resource := input.json.resources[_]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.encryption.defaultKmsKeyName
}

gc_issue["storage_encrypt"] {
    resource := input.json.resources[_]
    lower(resource.type) == "storage.v1.bucket"
    count(resource.properties.encryption.defaultKmsKeyName) == 0
}

storage_encrypt {
    lower(input.json.resources[_].type) == "storage.v1.bucket"
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
# Id: 336
#

default storage_versioning = null

gc_attribute_absence["storage_versioning"] {
    resource := input.json.resources[_]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.versioning
}

gc_issue["storage_versioning"] {
    resource := input.json.resources[_]
    lower(resource.type) == "storage.v1.bucket"
    contains(lower(resource.properties.acl[_].email), "logging")
    not resource.properties.versioning.enabled
}

storage_versioning {
    lower(input.json.resources[_].type) == "storage.v1.bucket"
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
# Id: 354
#

default storage_stack_logging = null

gc_attribute_absence["storage_stack_logging"] {
    resource := input.json.resources[_]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.logging
}

gc_issue["storage_stack_logging"] {
    resource := input.json.resources[_]
    lower(resource.type) == "storage.v1.bucket"
    contains(lower(resource.properties.acl[_].email), "logging")
    not resource.properties.logging
}

storage_stack_logging {
    lower(input.json.resources[_].type) == "storage.v1.bucket"
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

#
# Id: 389
#

default storage_logging = null

gc_issue["storage_logging"] {
    resource := input.json.resources[_]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.logging.logBucket
}

storage_logging {
    lower(input.json.resources[_].type) == "storage.v1.bucket"
    not gc_issue["storage_logging"]
}

storage_logging = false {
    gc_issue["storage_logging"]
}

storage_logging_err = "Storage Bucket does not have Access and Storage Logging enabled" {
    gc_issue["storage_logging"]
}

#
# Id: 390
#

default storage_versioning = null

gc_attribute_absence["storage_versioning"] {
    resource := input.json.resources[_]
    lower(resource.type) == "storage.v1.bucket"
    not resource.properties.acl
}

gc_issue["storage_versioning"] {
    resource := input.json.resources[_]
    lower(resource.type) == "storage.v1.bucket"
    acl := resource.properties.acl[_]
    contains(lower(acl.email), "logging")
    contains(lower(acl.entity), "allusers")
}

gc_issue["storage_versioning"] {
    resource := input.json.resources[_]
    lower(resource.type) == "storage.v1.bucket"
    acl := resource.properties.acl[_]
    contains(lower(acl.email), "logging")
    contains(lower(acl.entity), "allauthenticatedusers")
}

storage_versioning {
    lower(input.json.resources[_].type) == "storage.v1.bucket"
    not gc_issue["storage_versioning"]
    not gc_attribute_absence["storage_versioning"]
}

storage_versioning = false {
    gc_issue["storage_versioning"]
}

storage_versioning = false {
    gc_attribute_absence["storage_versioning"]
}

storage_versioning_err = "Storage Buckets with publicly accessible Stackdriver logs" {
    gc_issue["storage_versioning"]
}

storage_versioning_miss_err = "GCP Storage attribute acl missing in the resource" {
    gc_attribute_absence["storage_versioning"]
}
