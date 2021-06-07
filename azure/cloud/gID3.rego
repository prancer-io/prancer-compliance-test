#
# gID3
#

package rule

default rulepass = true

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups

rulepass = false {
    lower(input.type) == "microsoft.network/networksecuritygroups"
    count(nsg_allowed_inbound_port) > 0
}

metadata := {
    "Policy Code": "",
    "Type": "Cloud",
    "Product": "",
    "Language": "Cloud",
    "Policy Title": "Internet connectivity via tcp over insecure port",
    "Policy Description": "Identify network traffic coming from internet which is plain text FTP, Telnet or HTTP from Internet.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

ports := ["21", "23", "80"]

nsg_allowed_inbound_port["in_all"] {
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

nsg_allowed_inbound_port["in_single_port"] {
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == ports[_]
}

nsg_allowed_inbound_port["in_range"] {
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.destinationAddressPrefix == "*"
    port_range := split(rules.properties.destinationPortRange, "-")
    port := ports[_]
    to_number(port_range[0]) <= to_number(port)
    to_number(port_range[1]) >= to_number(port)
}

nsg_allowed_inbound_port["in_list"] {
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRanges[_] == ports[_]
}

nsg_allowed_inbound_port["in_range_list"] {
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.destinationAddressPrefix == "*"
    port_range := split(rules.properties.destinationPortRanges[_], "-")
    port := ports[_]
    to_number(port_range[0]) <= to_number(port)
    to_number(port_range[1]) >= to_number(port)
}
