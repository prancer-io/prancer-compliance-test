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
# Id: 334
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

storage_encrypt_err = "GCP Storage buckets are publicly accessible to all authenticated users" {
    gc_issue["storage_encrypt"]
}

storage_encrypt_miss_err = "GCP Storage bucket attribute encryption missing in the resource" {
    gc_attribute_absence["storage_encrypt"]
}
