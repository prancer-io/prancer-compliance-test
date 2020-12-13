package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2015-05-01-preview/servers/firewallrules

#
# PR-AZR-0082-ARM
#

default db_firewall = null

azure_attribute_absence["db_firewall"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/firewallrules"
    not resource.properties.startIpAddress
}

azure_attribute_absence["db_firewall"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/firewallrules"
    not resource.properties.endIpAddress
}

azure_issue["db_firewall"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/firewallrules"
    resource.properties.startIpAddress == "0.0.0.0"
}

azure_issue["db_firewall"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/firewallrules"
    resource.properties.endIpAddress == "0.0.0.0"
}

db_firewall {
    lower(input.resources[_].type) == "microsoft.sql/servers/firewallrules"
    not azure_issue["db_firewall"]
    not azure_attribute_absence["db_firewall"]
}

db_firewall = false {
    azure_issue["db_firewall"]
}

db_firewall = false {
    azure_attribute_absence["db_firewall"]
}

db_firewall_err = "SQL Server Firewall rules allow access to any Azure internal resources" {
    azure_issue["db_firewall"]
}

db_firewall_miss_err = "Firewall rule attribute startIpAddress/endIpAddress missing in the resource" {
    azure_attribute_absence["db_firewall"]
}
