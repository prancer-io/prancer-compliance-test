#
# PR-AZR-0043
#

package rule
default rulepass = true

# Azure Network Security Group allows Telnet (TCP Port 23)
# If NSG dose not allows Telnet TCP Port 23

# https://docs.microsoft.com/en-us/rest/api/virtualnetwork/networksecuritygroups/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Network/networkSecurityGroups/hardikVM-nsg

rulepass = false {
    lower(input.type) == "microsoft.network/networksecuritygroups"
    count(public_security_rules_any) > 0
}
rulepass = false {
    lower(input.type) == "microsoft.network/networksecuritygroups"
    count(public_security_rules_Internet) > 0
}
# Method for check rule
get_access[security_rule] {
    security_rule := input.properties.securityRules[_]
    security_rule.properties.access = "Allow"
    security_rule.properties.direction = "Inbound"
}

# Method for check rule
get_source_port[security_rule] {
    get_access[security_rule]
    security_rule.properties.sourcePortRange = "23"
}

# Method for check rule
get_destination_port[security_rule] {
    get_access[security_rule]
    security_rule.properties.destinationPortRange = "23"
}
# Method for check rule
get_source_PortRanges[security_rule] {
    get_access[security_rule]
    security_rule.properties.sourcePortRanges[_] = "23"
}
# Method for check rule
get_destination_PortRanges[security_rule] {
    get_access[security_rule]
    security_rule.properties.destinationPortRanges[_] = "23"
}
# Method for check rule
get_source_PortRange_Any[security_rule] {
    get_access[security_rule]
    security_rule.properties.sourcePortRange = "*"
}
# Method for check rule
get_destination_PortRange_Any[security_rule] {
    get_access[security_rule]
    security_rule.properties.destinationPortRange = "*"
}


# "securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == '*' && @.protocol = 'TCP'
# @.sourcePortRange == '23')].destinationPortRange contains _Port.inRange(23)
public_security_rules_any["internet_on_PortRange_23_any_source"] {
    some security_rule
    get_source_port[security_rule]
    security_rule.properties.sourceAddressPrefix = "*"
    security_rule.properties.protocol = "TCP"
}

public_security_rules_any["internet_on_PortRange_23_any_source"] {
    some security_rule
    get_destination_port[security_rule]
    security_rule.properties.sourceAddressPrefix = "*"
    security_rule.properties.protocol = "TCP"
}

# or "securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == '*' && @.protocol = 'TCP'
# @.sourcePortRanges[*] == '23')].destinationPortRanges[*] contains _Port.inRange(23)
public_security_rules_any["internet_on_PortRanges_23_any_source"] {
    some security_rule
    get_source_PortRanges[security_rule]
    security_rule.properties.sourceAddressPrefix = "*"
    security_rule.properties.protocol = "TCP"
}
public_security_rules_any["internet_on_PortRanges_23_any_source"] {
    some security_rule
    get_destination_PortRanges[security_rule]
    security_rule.properties.sourceAddressPrefix = "*"
    security_rule.properties.protocol = "TCP"
}

# or "securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == '*' && @.protocol = 'TCP'
# @.sourcePortRanges[*] == '*')].destinationPortRanges[*] contains _Port.inRange(23)
public_security_rules_any["internet_on_Any_PortRange_any_source"] {
    some security_rule
    get_source_PortRange_Any[security_rule]
    security_rule.properties.sourceAddressPrefix = "*"
    security_rule.properties.protocol = "TCP"
}
public_security_rules_any["internet_on_Any_PortRange_any_source"] {
    some security_rule
    get_destination_PortRange_Any[security_rule]
    security_rule.properties.sourceAddressPrefix = "*"
    security_rule.properties.protocol = "TCP"
}

# or securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == 'Internet' && @.protocol = 'TCP'
# @.sourcePortRange == '23')]‌.destinationPortRange contains _Port.inRange(23)
public_security_rules_Internet["internet_on_PortRange_23_Internet_source"] {
    some security_rule
    get_source_port[security_rule]
    security_rule.properties.sourceAddressPrefix = "Internet"
    security_rule.properties.protocol = "TCP"
}
public_security_rules_Internet["internet_on_PortRange_23_Internet_source"] {
    some security_rule
    get_destination_port[security_rule]
    security_rule.properties.sourceAddressPrefix = "Internet"
    security_rule.properties.protocol = "TCP"
}
# or "securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == 'Internet' && @.protocol = 'TCP'
#  @.sourcePortRanges[*] == '23')].destinationPortRanges[*] contains _Port.inRange(23)
public_security_rules_Internet["internet_on_PortRanges_23_Internet_source"] {
    some security_rule
    get_source_PortRanges[security_rule]
    security_rule.properties.sourceAddressPrefix = "Internet"
    security_rule.properties.protocol = "TCP"
}
public_security_rules_Internet["internet_on_PortRanges_23_Internet_source"] {
    some security_rule
    get_destination_PortRanges[security_rule]
    security_rule.properties.sourceAddressPrefix = "Internet"
    security_rule.properties.protocol = "TCP"
}
# or "securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == 'Internet' && @.protocol = 'TCP'
# @.sourcePortRanges[*] == '*')].destinationPortRanges[*] contains _Port.inRange(23)
public_security_rules_Internet["internet_on_Any_PortRange_Internet_source"] {
    some security_rule
    get_source_PortRange_Any[security_rule]
    security_rule.properties.sourceAddressPrefix = "Internet"
    security_rule.properties.protocol = "TCP"
}
public_security_rules_Internet["internet_on_Any_PortRange_Internet_source"] {
    some security_rule
    get_destination_PortRange_Any[security_rule]
    security_rule.properties.sourceAddressPrefix = "Internet"
    security_rule.properties.protocol = "TCP"
}