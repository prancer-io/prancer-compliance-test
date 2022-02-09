package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/disks

#
# PR-GCP-TRF-DISK-001
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
    "Policy Code": "PR-GCP-TRF-DISK-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP VM disks not encrypted with Customer-Supplied Encryption Keys (CSEK)",
    "Policy Description": "This policy identifies VM disks which are not encrypted with Customer-Supplied Encryption Keys (CSEK). If you provide your own encryption keys, Compute Engine uses your key to protect the Google-generated keys used to encrypt and decrypt your data. It is recommended to use VM disks encrypted with CSEK for business-critical VM instances.",
    "Resource Type": "google_compute_disk",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/disks"
}


#
# PR-GCP-TRF-INST-008
#

default compute_disk_csek = null

gc_issue["compute_disk_csek"] {
    resource := input.resources[i]
    lower(resource.type) == "google_compute_disk"
    not resource.properties.source_snapshot_encryption_key.sha256
}

gc_issue["compute_disk_csek"] {
    resource := input.resources[i]
    lower(resource.type) == "google_compute_disk"
    count(resource.properties.source_snapshot_encryption_key.sha256) == 0
}

gc_issue["compute_disk_csek"] {
    resource := input.resources[i]
    lower(resource.type) == "google_compute_disk"
    resource.properties.source_snapshot_encryption_key.sha256 == null
}

compute_disk_csek {
    lower(input.resources[i].type) == "google_compute_disk"
    not gc_issue["compute_disk_csek"]
}

compute_disk_csek = false {
    gc_issue["compute_disk_csek"]
}

compute_disk_csek_err = "Ensure GCP GCE Disk snapshot is encrypted with CSEK" {
    gc_issue["compute_disk_csek"]
}

compute_disk_csek_metadata := {
    "Policy Code": "PR-GCP-TRF-INST-008",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP GCE Disk snapshot is encrypted with CSEK",
    "Policy Description": "This policy identifies GCP GCE Disk snapshots that are not encrypted with CSEK. It is recommended that to avoid data leakage provide your own encryption keys, Compute Engine uses your key to protect the Google-generated keys used to encrypt and decrypt your data. Only users who can provide the correct key can use resources protected by a customer-supplied encryption key",
    "Resource Type": "google_compute_disk",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}
