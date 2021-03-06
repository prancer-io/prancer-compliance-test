#
# PR-AZR-0040
#

package rule
default rulepass = true

# next generation firewall is set to OFF in Security Center
# IF next generation firewall is set to on port 25 in Security Center

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

metadata := {
    "Policy Code": "PR-AZR-0040",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure Network Security Group allows SMTP (TCP Port 25)",
    "Policy Description": "This policy detects any NSG rule that allows SMTP traffic on TCP port 25 from the internet. Review your list of NSG rules to ensure that your resources are not exposed._x005F_x000D_ As a best practice, restrict SMTP solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/virtualnetwork/networksecuritygroups/get"
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
    security_rule.properties.sourcePortRange = "25"
}

# Method for check rule
get_destination_port[security_rule] {
    get_access[security_rule]
    security_rule.properties.destinationPortRange = "25"
}
# Method for check rule
get_source_PortRanges[security_rule] {
    get_access[security_rule]
    security_rule.properties.sourcePortRanges[_] = "25"
}
# Method for check rule
get_destination_PortRanges[security_rule] {
    get_access[security_rule]
    security_rule.properties.destinationPortRanges[_] = "25"
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


# "securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == '*'
# @.sourcePortRange == '25')].destinationPortRange contains _Port.inRange(25)
public_security_rules_any["internet_on_PortRange_25_any_source"] {
    some security_rule
    get_source_port[security_rule]
    security_rule.properties.sourceAddressPrefix = "*"
}

public_security_rules_any["internet_on_PortRange_25_any_source"] {
    some security_rule
    get_destination_port[security_rule]
    security_rule.properties.sourceAddressPrefix = "*"
}

# or "securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == '*'
# @.sourcePortRanges[*] == '25')].destinationPortRanges[*] contains _Port.inRange(25)
public_security_rules_any["internet_on_PortRanges_25_any_source"] {
    some security_rule
    get_source_PortRanges[security_rule]
    security_rule.properties.sourceAddressPrefix = "*"
}
public_security_rules_any["internet_on_PortRanges_25_any_source"] {
    some security_rule
    get_destination_PortRanges[security_rule]
    security_rule.properties.sourceAddressPrefix = "*"
}

# or "securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == '*'
# @.sourcePortRanges[*] == '*')].destinationPortRanges[*] contains _Port.inRange(25)
public_security_rules_any["internet_on_Any_PortRange_any_source"] {
    some security_rule
    get_source_PortRange_Any[security_rule]
    security_rule.properties.sourceAddressPrefix = "*"
}
public_security_rules_any["internet_on_Any_PortRange_any_source"] {
    some security_rule
    get_destination_PortRange_Any[security_rule]
    security_rule.properties.sourceAddressPrefix = "*"
}

# or securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == 'Internet'
# @.sourcePortRange == '25')]‌.destinationPortRange contains _Port.inRange(25)
public_security_rules_Internet["internet_on_PortRange_25_Internet_source"] {
    some security_rule
    get_source_port[security_rule]
    security_rule.properties.sourceAddressPrefix = "Internet"
}
public_security_rules_Internet["internet_on_PortRange_25_Internet_source"] {
    some security_rule
    get_destination_port[security_rule]
    security_rule.properties.sourceAddressPrefix = "Internet"
}
# or "securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == 'Internet'
#  @.sourcePortRanges[*] == '25')].destinationPortRanges[*] contains _Port.inRange(25)
public_security_rules_Internet["internet_on_PortRanges_25_Internet_source"] {
    some security_rule
    get_source_PortRanges[security_rule]
    security_rule.properties.sourceAddressPrefix = "Internet"
}
public_security_rules_Internet["internet_on_PortRanges_25_Internet_source"] {
    some security_rule
    get_destination_PortRanges[security_rule]
    security_rule.properties.sourceAddressPrefix = "Internet"
}
# or "securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == 'Internet'
# @.sourcePortRanges[*] == '*')].destinationPortRanges[*] contains _Port.inRange(25)
public_security_rules_Internet["internet_on_Any_PortRange_Internet_source"] {
    some security_rule
    get_source_PortRange_Any[security_rule]
    security_rule.properties.sourceAddressPrefix = "Internet"
}
public_security_rules_Internet["internet_on_Any_PortRange_Internet_source"] {
    some security_rule
    get_destination_PortRange_Any[security_rule]
    security_rule.properties.sourceAddressPrefix = "Internet"
}