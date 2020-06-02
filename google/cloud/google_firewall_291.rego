package rule
default rulepass = true

# GCP Firewall with Inbound rule overly permissive to All Traffic
# If GCP Firewall with Inbound rule overly not permissive to All Traffic
# API and Response Reference : https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/list
rulepass = false {                                      
   count(allow_all_traffic) > 0
}

# 'sourceRanges[*] contains 0.0.0.0/0 and allowed[*].IPProtocol equals all'
allow_all_traffic["ALLOW_FROM_ANYWHERE"] {
   input.sourceRanges[_]="0.0.0.0/0"
}
allow_all_traffic["ALLOW_FROM_IPPROTOCOL"] {
   input.allowed[_]["IPProtocol"]="all"
}