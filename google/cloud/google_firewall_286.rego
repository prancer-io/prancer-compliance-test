#
# PR-GCP-0016
#

package rule
default rulepass = false

# Firewall rule allows internet traffic to RDP port (3389)
#  If Firewall rule not allows internet traffic to RDP port (3389)
# API and Response Reference : https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/list
rulepass = true {
    lower(input.type) == "compute.v1.firewall"
    count(allowport) > 0
}

get_access[security_rule] {
    security_rule := input
    security_rule.disabled= false
}

# (sourceRanges[*] contains 0.0.0.0/0 and allowed[*].ports[3389] )
allowport["ALLOW_PORT"] {
    get_access[security_rule]
    input.sourceRanges[_]="0.0.0.0/0"
    input.allowed[_].ports[_]="3389"
}

# (sourceRanges[*] contains 0.0.0.0/0 and allowed[*].IPProtocol[*])
allowport["IPProtocol_TCP"] {
    get_access[security_rule]
    input.sourceRanges[_]="0.0.0.0/0"
    input.allowed[_].IPProtocol="all"
}

metadata := {
    "Policy Code": "PR-GCP-0016",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Firewall rule allows internet traffic to RDP port (3389)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on RDP port (3389) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/list"
}
