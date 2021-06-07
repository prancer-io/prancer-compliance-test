#
# PR-GCP-0074
#

package rule
default rulepass = false

# enableFlowLogs is false or enableFlowLogs does not exist'

rulepass = true {
    lower(input.type) == "compute.v1.instance"
    count(enableFlowLogs) >= 2
}

# nodePools[*].config.serviceAccount contains default
enableFlowLogs["input.enableFlowLogs"] {
    input.enableFlowLogs = "false"

}

enableFlowLogs["input.enableFlowLogs"] {
    not input.enableFlowLogs
}

metadata := {
    "Policy Code": "PR-GCP-0074",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP VPC Flow logs for the subnet is set to Off",
    "Policy Description": "This policy identifies the subnets in VPC Network which have Flow logs disabled. It enables to capture information about the IP traffic going to and from network interfaces in VPC Subnets.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
