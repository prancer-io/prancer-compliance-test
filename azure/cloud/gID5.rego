#
# gID5
#

package rule

default rulepass = true

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups

rulepass = false {
    lower(input.type) == "microsoft.network/networksecuritygroups"
    count(nsg_allowed_inbound_port) > 0
}

ports := ["11211"]

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

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/2019-04-01/virtualnetworks

rulepass {
    input.properties.enableDdosProtection == true
}

metadata := {
    "Policy Code": "",
    "Type": "Cloud",
    "Product": "",
    "Language": "Cloud",
    "Policy Title": "Memcached DDoS attack attempted",
    "Policy Description": "Memcached is a general-purpose distributed memory caching system. It is often used to speed up dynamic database-driven websites by caching data and objects in RAM to reduce the number of times an external data source (such as a database or API) must be read. It is reported that Memcache versions 1.5.5 and below are vulnerable to DDoS amplification attack. This policy aims at finding such attacks and generate alerts.",
    "Compliance": [],
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}
