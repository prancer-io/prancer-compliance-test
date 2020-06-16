package rule
default rulepass = true

# Azure Network Security Group (NSG) allows SSH traffic from internet on port "22"
# If NSG dose not allows SSH traffic from internet on port "22"

# https://docs.microsoft.com/en-us/rest/api/virtualnetwork/networksecuritygroups/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Network/networkSecurityGroups/hardikVM-nsg

rulepass = false {
   count(public_security_rules_any) > 0
}
rulepass = false {
   count(public_security_rules_Internet) > 0
}
# Method for check rule
get_access[security_rule] {
    security_rule := input.properties.securityRules[_]
    security_rule.properties.access == "Allow"
    security_rule.properties.direction == "Inbound"
}

# Method for check rule
get_source_port[security_rule] {
    get_access[security_rule]
    security_rule.properties.sourcePortRange == "22"
}

# Method for check rule
get_destination_port[security_rule] {
    get_access[security_rule]
    security_rule.properties.destinationPortRange == "22"
}
# Method for check rule
get_source_PortRanges[security_rule] {
    get_access[security_rule]
    security_rule.properties.sourcePortRanges[_] == "22"
}
# Method for check rule
get_destination_PortRanges[security_rule] {
    get_access[security_rule]
    security_rule.properties.destinationPortRanges[_] == "22"
}
# Method for check rule
get_source_PortRange_Any[security_rule] {
    get_access[security_rule]
    security_rule.properties.sourcePortRange == "*"
}
# Method for check rule
get_destination_PortRange_Any[security_rule] {
    get_access[security_rule]
    security_rule.properties.destinationPortRange == "*"
}


# "securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == '*' 
# @.sourcePortRange == '22')].destinationPortRange contains _Port.inRange(22)
public_security_rules_any["internet_on_PortRange_22_any_source"] {
    some security_rule
    get_source_port[security_rule]
    security_rule.properties.sourceAddressPrefix == "*"
}

public_security_rules_any["internet_on_PortRange_22_any_source"] {
    some security_rule
    get_destination_port[security_rule]
    security_rule.properties.sourceAddressPrefix == "*"
}

# or "securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == '*'
# @.sourcePortRanges[*] == '22')].destinationPortRanges[*] contains _Port.inRange(22)
public_security_rules_any["internet_on_PortRanges_22_any_source"] {
    some security_rule
    get_source_PortRanges[security_rule]
    security_rule.properties.sourceAddressPrefix == "*"
}
public_security_rules_any["internet_on_PortRanges_22_any_source"] {
    some security_rule
    get_destination_PortRanges[security_rule]
    security_rule.properties.sourceAddressPrefix == "*"
}

# or "securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == '*'
# @.sourcePortRanges[*] == '*')].destinationPortRanges[*] contains _Port.inRange(22)
public_security_rules_any["internet_on_Any_PortRange_any_source"] {
    some security_rule
    get_source_PortRange_Any[security_rule]
    security_rule.properties.sourceAddressPrefix == "*"
}
public_security_rules_any["internet_on_Any_PortRange_any_source"] {
    some security_rule
    get_destination_PortRange_Any[security_rule]
    security_rule.properties.sourceAddressPrefix == "*"
}

# or securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix = 'Internet' 
# @.sourcePortRange == '22')]‌.destinationPortRange contains _Port.inRange(22) 
public_security_rules_Internet["internet_on_PortRange_22_Internet_source"] {
    some security_rule
    get_source_port[security_rule]
    security_rule.properties.sourceAddressPrefix == "Internet"
}
public_security_rules_Internet["internet_on_PortRange_22_Internet_source"] {
    some security_rule
    get_destination_port[security_rule]
    security_rule.properties.sourceAddressPrefix == "Internet"
}
# or "securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == 'Internet'
#  @.sourcePortRanges[*] == '22')].destinationPortRanges[*] contains _Port.inRange(22)
public_security_rules_Internet["internet_on_PortRanges_22_Internet_source"] {
    some security_rule
    get_source_PortRanges[security_rule]
    security_rule.properties.sourceAddressPrefix == "Internet"
}
public_security_rules_Internet["internet_on_PortRanges_22_Internet_source"] {
    some security_rule
    get_destination_PortRanges[security_rule]
    security_rule.properties.sourceAddressPrefix == "Internet"
}
# or "securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == 'Internet'
# @.sourcePortRanges[*] == '*')].destinationPortRanges[*] contains _Port.inRange(22)
public_security_rules_Internet["internet_on_Any_PortRange_Internet_source"] {
    some security_rule
    get_source_PortRange_Any[security_rule]
    security_rule.properties.sourceAddressPrefix == "Internet"
}
public_security_rules_Internet["internet_on_Any_PortRange_Internet_source"] {
    some security_rule
    get_destination_PortRange_Any[security_rule]
    security_rule.properties.sourceAddressPrefix == "Internet"
}
