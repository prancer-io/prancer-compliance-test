#
# PR-GCP-0093
#

package rule
default rulepass = false

# VM Instances without any Label information
rulepass = true {
    lower(input.type) == "compute.v1.instance"
    count(labels) == 1
}

# $.labels[*] == null
labels["label"] {
    not input.labels
}

metadata := {
    "Policy Code": "PR-GCP-0093",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "VM Instances without any Label information",
    "Policy Description": "VM instance does not have any Labels. Labels can be used for easy identification and searches.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
