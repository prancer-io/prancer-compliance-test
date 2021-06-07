#
# PR-GCP-0070
#

package rule
default rulepass = false

# GCP VM instances have IP forwarding enabled

rulepass = true {
    lower(input.type) == "compute.v1.instance"
    count(ipforwarding) == 1
}

# 'canIpForward is false'
ipforwarding[input.id] {
    input.canIpForward=true
}

metadata := {
    "Policy Code": "PR-GCP-0070",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP VM instances have IP forwarding enabled",
    "Policy Description": "This policy identifies VM instances have IP forwarding enabled. IP Forwarding could open unintended and undesirable communication paths and allows VM instances to send and receive packets with the non-matching destination or source IPs. To enable source and destination IP match check, disable the IP Forwarding.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
