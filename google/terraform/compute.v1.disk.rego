package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/disks

#
# PR-GCP-0069-TRF
#

gc_issue["disk_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_disk"
    not resource.properties.disk_encryption_key
}

gc_issue["disk_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_disk"
    resource.properties.disk_encryption_key == null
}

gc_issue["disk_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_disk"
    count(resource.properties.disk_encryption_key) == 0
}

disk_encrypt {
    lower(input.resources[_].type) == "google_compute_disk"
    not gc_issue["disk_encrypt"]
}

disk_encrypt = false {
    gc_issue["disk_encrypt"]
}

disk_encrypt_err = "GCP VM disks not encrypted with Customer-Supplied Encryption Keys (CSEK)" {
    gc_issue["disk_encrypt"]
}

disk_encrypt_metadata := {
    "Policy Code": "PR-GCP-0069-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP VM disks not encrypted with Customer-Supplied Encryption Keys (CSEK)",
    "Policy Description": "This policy identifies VM disks which are not encrypted with Customer-Supplied Encryption Keys (CSEK). If you provide your own encryption keys, Compute Engine uses your key to protect the Google-generated keys used to encrypt and decrypt your data. It is recommended to use VM disks encrypted with CSEK for business-critical VM instances.",
    "Resource Type": "google_compute_disk",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/disks"
}
