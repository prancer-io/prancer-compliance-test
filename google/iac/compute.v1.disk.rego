package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/disks

#
# PR-GCP-0069-CFR
#

default disk_encrypt = null

gc_issue["disk_encrypt"] {
    resource := input.json.resources[_]
    lower(resource.type) == "compute.v1.disk"
    not resource.properties.diskEncryptionKey
}

disk_encrypt {
    lower(input.json.resources[_].type) == "compute.v1.disk"
    not gc_issue["disk_encrypt"]
}

disk_encrypt = false {
    gc_issue["disk_encrypt"]
}

disk_encrypt_err = "GCP VM disks not encrypted with Customer-Supplied Encryption Keys (CSEK)" {
    gc_issue["disk_encrypt"]
}
