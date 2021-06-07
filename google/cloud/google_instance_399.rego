#
# PR-GCP-0094
#

package rule
default rulepass = false

# VM instances without metadata, zone or label information

rulepass = true {
    lower(input.type) == "compute.v1.instance"
    count(scheduling) >= 1
}

# '$.labels equals null or
scheduling["labels"] {
    not input.labels
}

# $.zone equals null or
scheduling["zone"] {
    input.zone
}

# $.metadata equals null'
scheduling["metadata"] {
    not input.metadata
}

metadata := {
    "Policy Code": "PR-GCP-0094",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "VM instances without metadata, zone or label information",
    "Policy Description": "Checks to ensure that VM instances have proper metadata, zone and label information tags. These tags can be used for easier identification and searches.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": ""
}

