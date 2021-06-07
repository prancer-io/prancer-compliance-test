#
# PR-GCP-0092
#

package rule
default rulepass = false

# VM Instances without any custom metadata information
rulepass = true {
    lower(input.type) == "compute.v1.instance"
    count(metadata) == 1
}

# $.metadata.items[*] == null'
metadata["metadata_items"] {
    not input.metadata
}

metadata := {
    "Policy Code": "PR-GCP-0092",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "VM Instances without any Custom metadata information",
    "Policy Description": "VM instance does not have any Custom metadata. Custom metadata can be used for easy identification and searches.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
