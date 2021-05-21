package rule

# https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computedisk

#
# DISK_CMEK_DISABLED
# DISK_CSEK_DISABLED
#

default disk_cmek_disabled = null

gc_issue["disk_cmek_disabled"] {
    lower(input.kind) == "computedisk"
    not input.spec.diskEncryptionKey
}

disk_cmek_disabled {
    lower(input.kind) == "computedisk"
    not gc_issue["disk_cmek_disabled"]
}

disk_cmek_disabled = false {
    gc_issue["disk_cmek_disabled"]
}

disk_cmek_disabled_err = "Disks on this VM are not encrypted with CMEK or CSEC." {
    gc_issue["disk_cmek_disabled"]
}

disk_cmek_disabled_metadata := {
    "Policy Code": "DISK_CMEK_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Disk CMEK Disabled",
    "Policy Description": "Disks on this VM are not encrypted with CMEK or CSEC.",
    "Resource Type": "ComputeDisk",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computedisk"
}
