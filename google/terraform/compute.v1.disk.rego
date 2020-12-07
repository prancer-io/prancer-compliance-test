package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/disks

#
# Id: 339
#

default disk_encrypt = null

gc_issue["disk_encrypt"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_compute_disk"
    not resource.properties.disk_encryption_key
}

disk_encrypt {
    lower(input.json.resources[_].type) == "google_compute_disk"
    not gc_issue["disk_encrypt"]
}

disk_encrypt = false {
    gc_issue["disk_encrypt"]
}

disk_encrypt_err = "GCP VM disks not encrypted with Customer-Supplied Encryption Keys (CSEK)" {
    gc_issue["disk_encrypt"]
}
