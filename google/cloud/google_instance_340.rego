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