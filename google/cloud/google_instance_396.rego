#
# PR-GCP-0091
#

package rule
default rulepass = false

# VM Instances enabled with Pre-Emptible termination
rulepass = true {
    lower(input.type) == "compute.v1.instance"
    count(scheduling) == 1
}

# '$.scheduling.preemptible == true'
scheduling["scheduling_preemptible"] {
    input.scheduling.preemptible = true
}

metadata := {
    "Policy Code": "PR-GCP-0091",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "VM Instances enabled with Pre-Emptible termination",
    "Policy Description": "Checks to verify if any VM instance is initiated with the flag 'Pre-Emptible termination' set to True. Setting this instance to True implies that this VM instance will shut down within 24 hours or can also be terminated by a Service Engine when high demand is encountered. While this might save costs, it can also lead to unexpected loss of service when the VM instance is terminated.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
