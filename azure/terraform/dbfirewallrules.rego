package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2015-05-01-preview/servers/firewallrules

#
# SQL Server Firewall rules allow access to any Azure internal resources (291)
#

default db_firewall = null

azure_attribute_absence["db_firewall"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_sql_firewall_rule"
    not resource.properties.start_ip_address
}

azure_attribute_absence["db_firewall"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_sql_firewall_rule"
    not resource.properties.end_ip_address
}

azure_issue["db_firewall"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_sql_firewall_rule"
    resource.properties.start_ip_address == "0.0.0.0"
}

azure_issue["db_firewall"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_sql_firewall_rule"
    resource.properties.end_ip_address == "0.0.0.0"
}

db_firewall {
    lower(input.json.resources[_].type) == "azurerm_sql_firewall_rule"
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

db_firewall_miss_err = "Firewall rule attribute start_ip_address/end_ip_address missing in the resource" {
    azure_attribute_absence["db_firewall"]
}
