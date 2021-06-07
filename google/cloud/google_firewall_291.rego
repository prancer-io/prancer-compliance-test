#
# PR-GCP-0021
#

package rule
default rulepass = true

# GCP Firewall with Inbound rule overly permissive to All Traffic
# If GCP Firewall with Inbound rule overly not permissive to All Traffic
# API and Response Reference : https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/list
rulepass = false {
    lower(input.type) == "compute.v1.firewall"
    count(allow_all_traffic) > 0
}

# 'sourceRanges[*] contains 0.0.0.0/0 and allowed[*].IPProtocol equals all'
allow_all_traffic["ALLOW_FROM_ANYWHERE"] {
    input.sourceRanges[_]="0.0.0.0/0"
}
allow_all_traffic["ALLOW_FROM_IPPROTOCOL"] {
    input.allowed[_]["IPProtocol"]="all"
}

metadata := {
    "Policy Code": "PR-GCP-0021",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Firewall with Inbound rule overly permissive to All Traffic",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/list"
}
