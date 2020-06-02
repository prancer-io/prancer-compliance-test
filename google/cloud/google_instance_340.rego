package rule
default rulepass = false

# GCP VM instances have IP forwarding enabled

rulepass = true {                                      
   count(ipforwarding) == 1
}

# 'canIpForward is false'
ipforwarding[input.id] {
   input.canIpForward=true
}