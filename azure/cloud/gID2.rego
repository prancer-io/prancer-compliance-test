#
# gID2
#

package rule

default rulepass = true

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups

rulepass = false {
    input.type == "Microsoft.Network/networkSecurityGroups"
    count(nsg_allowed_outbound_port) > 0
}

ports := ["8545", "30303"]

nsg_allowed_outbound_port["in_all"] {
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Outbound"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

nsg_allowed_outbound_port["in_single_port"] {
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Outbound"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == ports[_]
}

nsg_allowed_outbound_port["in_range"] {
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Outbound"
    rules.properties.destinationAddressPrefix == "*"
    port_range := split(rules.properties.destinationPortRange, "-")
    port := ports[_]
    port_range[0] <= port
    port_range[1] >= port
}

nsg_allowed_outbound_port["in_list"] {
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Outbound"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRanges[_] == ports[_]
}

nsg_allowed_outbound_port["in_range_list"] {
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Outbound"
    rules.properties.destinationAddressPrefix == "*"
    port_range := split(rules.properties.destinationPortRanges[_], "-")
    port := ports[_]
    port_range[0] <= port
    port_range[1] >= port
}
