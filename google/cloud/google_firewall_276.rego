package rule
default rulepass = true

# Firewall rule allows internet traffic to DNS port (53)
# if Firewall rule not allows internet traffic to DNS port (53)

# API and Response Reference : https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/list

rulepass = false {                                      
   count(allowport) > 0
}
get_access[security_rule] {
   security_rule := input
   security_rule.disabled= false 
}

# (sourceRanges[*] contains 0.0.0.0/0 and allowed[*].ports[53] )
allowport["ALLOW_PROT_SOURCERANGE_IN_INTERNET"] {
   get_access[security_rule]
   input.sourceRanges[_]="0.0.0.0/0"
   input.allowed[_].ports[_]="53"
}
# (sourceRanges[*] contains 0.0.0.0/0 and allowed[*].IPProtocol[*])
allowport["ALLOW_IPPROTOCOL_SOURCERANGE_IN_INTERNET"] {
   get_access[security_rule]
   input.sourceRanges[_]="0.0.0.0/0"
   input.allowed[_].IPProtocol="all"
}
