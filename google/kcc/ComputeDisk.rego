package rule

# https://github.com/GoogleCloudPlatform/k8s-config-connector/blob/master/samples/resources/computedisk/zonal-compute-disk/compute_v1beta1_computedisk.yaml

#
# PR-GCP-0069-KCC
#

default disk_encrypt = null

gc_issue["disk_encrypt"] {
    lower(input.kind) == "computedisk"
    not input.spec.diskEncryptionKey
}

disk_encrypt {
    lower(input.kind) == "computedisk"
    not gc_issue["disk_encrypt"]
}

disk_encrypt = false {
    gc_issue["disk_encrypt"]
}

disk_encrypt_err = "GCP VM disks not encrypted with Customer-Supplied Encryption Keys (CSEK)" {
    gc_issue["disk_encrypt"]
}
