#
# PR-AZR-0034
#

package rule
default rulepass = true

# Azure Network Security Group allows ICMP (Ping)
# If NSG dose not allows ICMP (Ping)

# https://docs.microsoft.com/en-us/rest/api/virtualnetwork/networksecuritygroups/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Network/networkSecurityGroups/hardikVM-nsg

rulepass = false {
    lower(input.type) == "microsoft.network/networksecuritygroups"
    count(public_security_rules_icmp) > 0
}

metadata := {
    "Policy Code": "PR-AZR-0034",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure Network Security Group allows ICMP (Ping)",
    "Policy Description": "ICMP is used by devices to communicate error messages and status. While ICMP is useful for  diagnostics and troubleshooting, it can also be used to exploit or disrupt systems._x005F_x000D_  _x005F_x000D_ This policy detects any NSG rule that allows ICMP (Ping) traffic from the internet. Review your list of NSG rules to ensure that your resources are not exposed._x005F_x000D_ As a best practice, restrict ICMP (Ping) solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.",
    "Compliance": [],
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/virtualnetwork/networksecuritygroups/get"
}
# Method for check rule
get_porotocol_sourcePortRange[security_rule] {
    security_rule := input.properties.securityRules[_]
    security_rule.properties.access = "Allow"
    security_rule.properties.direction = "Inbound"
    security_rule.properties.sourcePortRange = "*"
    security_rule.properties.protocol = "ICMP"
}
get_porotocol_destinationPortRange[security_rule] {
    security_rule := input.properties.securityRules[_]
    security_rule.properties.access = "Allow"
    security_rule.properties.direction = "Inbound"
    security_rule.properties.destinationPortRange = "*"
    security_rule.properties.protocol = "ICMP"
}
# or "securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == '*' &&
# @.protocol == 'ICMP'&& @.sourcePortRanges[*] == '*')].destinationPortRanges[*] contains _Port.inRange(*)
public_security_rules_icmp["internet_on_icmp_protocol_any_source"] {
    some security_rule
    get_porotocol_sourcePortRange[security_rule]
    get_porotocol_destinationPortRange[security_rule]
    security_rule.properties.sourceAddressPrefix = "*"
}

# or "securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == 'Internet' &&
# @.protocol == 'ICMP' && @.sourcePortRanges[*] == '*')].destinationPortRanges[*] contains _Port.inRange(*)
public_security_rules_icmp["internet_on_Any_PortRange_Internet_source"] {
    some security_rule
    get_porotocol_sourcePortRange[security_rule]
    get_porotocol_destinationPortRange[security_rule]
    security_rule.properties.sourceAddressPrefix = "Internet"
}