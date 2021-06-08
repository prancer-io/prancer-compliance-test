#
# gID6
#

package rule
default rulepass = true

# Publicly exposed DB Ports
# If NSG Publicly dose not exposed DB Ports test will  pass

# https://docs.microsoft.com/en-us/rest/api/virtualnetwork/networksecuritygroups/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Network/networkSecurityGroups/hardikVM-nsg

rulepass = false {
    lower(input.type) == "microsoft.network/virtualnetworks"
    count(public_security_rules_any) > 0
}
rulepass = false {
    lower(input.type) == "microsoft.network/virtualnetworks"
    count(public_security_rules_Internet) > 0
}

metadata := {
    "Policy Code": "",
    "Type": "Cloud",
    "Product": "",
    "Language": "Cloud",
    "Policy Title": "Publicly exposed DB Ports",
    "Policy Description": "DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).",
    "Compliance": [],
    "Resource Type": "microsoft.network/virtualnetworks",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/virtualnetwork/networksecuritygroups/get"
}
# Method for check rule
get_access[security_rule] {
    security_rule := input.properties.securityRules[_]
    security_rule.properties.access = "Allow"
    security_rule.properties.direction = "Inbound"
}

sourcePort := ["1433", "1521", "3306", "5000", "5432", "5984", "6379", "6380", "8080", "9042", "11211", "27017", "28015", "29015", "50000"]

# Method for check rule
get_source_port[security_rule] {
    get_access[security_rule]
    sourcePort[_] == security_rule.properties.sourcePortRange
}

# Method for check rule
get_source_port_ranges[security_rule] {
    get_access[security_rule]
    # some source_port_range
    source_port_range := security_rule.properties.sourcePortRanges[_]
    sourcePort[_] == source_port_range
}

# Method for check rule
get_destination_port[security_rule] {
    get_access[security_rule]
    sourcePort[_] == security_rule.properties.destinationPortRange
}

# Method for check rule
get_destination_port_ranges[security_rule] {
    get_access[security_rule]
    # some destination_port_range
    destination_port_range := security_rule.properties.destinationPortRanges[_]
    sourcePort[_] = destination_port_range
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
# @.sourcePortRange == '1433, 1521, 3306, 5000, 5432, 5984, 6379, 6380, 8080, 9042, 11211, 27017, 28015, 29015, 50000')].destinationPortRange contains _Port.inRange(1433, 1521, 3306, 5000, 5432, 5984, 6379, 6380, 8080, 9042, 11211, 27017, 28015, 29015, 50000)
public_security_rules_any["internet_on_DB_port_any_source"] {
    some security_rule
    get_source_port[security_rule]
    security_rule.properties.sourceAddressPrefix == "*"
}

public_security_rules_any["internet_on_DB_port_any_source_range"] {
    some security_rule
    get_source_port_ranges[security_rule]
    security_rule.properties.sourceAddressPrefix == "*"
}

public_security_rules_any["internet_on_DB_port_any_destination"] {
    some security_rule
    get_destination_port[security_rule]
    security_rule.properties.sourceAddressPrefix == "*"
}

public_security_rules_any["internet_on_DB_port_any_destination_range"] {
    some security_rule
    get_destination_port_ranges[security_rule]
    security_rule.properties.sourceAddressPrefix == "*"
}


# or "securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == '*'
# @.sourcePortRanges[*] == '*')].destinationPortRanges[*] contains _Port.inRange(1433, 1521, 3306, 5000, 5432, 5984, 6379, 6380, 8080, 9042, 11211, 27017, 28015, 29015, 50000)
public_security_rules_any["internet_on_Any_port_any_source"] {
    some security_rule
    get_source_PortRange_Any[security_rule]
    security_rule.properties.sourceAddressPrefix == "*"
}

public_security_rules_any["internet_on_Any_port_any_destination"] {
    some security_rule
    get_destination_PortRange_Any[security_rule]
    security_rule.properties.sourceAddressPrefix == "*"
}

# or securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix = 'Internet'
# @.sourcePortRange == '1433, 1521, 3306, 5000, 5432, 5984, 6379, 6380, 8080, 9042, 11211, 27017, 28015, 29015, 50000')]‌.destinationPortRange contains _Port.inRange(1433, 1521, 3306, 5000, 5432, 5984, 6379, 6380, 8080, 9042, 11211, 27017, 28015, 29015, 50000)
public_security_rules_Internet["internet_on_PortRange_DB_port_Internet_source"] {
    some security_rule
    get_source_port[security_rule]
    security_rule.properties.sourceAddressPrefix == "Internet"
}

public_security_rules_Internet["internet_on_PortRange_DB_port_Internet_source_range"] {
    some security_rule
    get_source_port_ranges[security_rule]
    security_rule.properties.sourceAddressPrefix == "Internet"
}

public_security_rules_Internet["internet_on_PortRange_DB_port_Internet_destination"] {
    some security_rule
    get_destination_port[security_rule]
    security_rule.properties.sourceAddressPrefix == "Internet"
}

public_security_rules_Internet["internet_on_PortRange_DB_port_Internet_destination_range"] {
    some security_rule
    get_destination_port_ranges[security_rule]
    security_rule.properties.sourceAddressPrefix == "Internet"
}

# or "securityRules[?(@.access == 'Allow' && @.direction == 'Inbound' && @.sourceAddressPrefix == 'Internet'
# @.sourcePortRanges[*] == '*')].destinationPortRanges[*] contains _Port.inRange(1433, 1521, 3306, 5000, 5432, 5984, 6379, 6380, 8080, 9042, 11211, 27017, 28015, 29015, 50000)
public_security_rules_Internet["internet_on_Any_PortRange_Internet_source"] {
    some security_rule
    get_source_PortRange_Any[security_rule]
    security_rule.properties.sourceAddressPrefix == "Internet"
}

public_security_rules_Internet["internet_on_Any_PortRange_Internet_destnation"] {
    some security_rule
    get_destination_PortRange_Any[security_rule]
    security_rule.properties.sourceAddressPrefix == "Internet"
}
