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