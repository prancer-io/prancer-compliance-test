package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2015-05-01-preview/servers/firewallrules

#
# PR-AZR-0082-TRF
#

default db_firewall = null

azure_attribute_absence["db_firewall"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_firewall_rule"
    not resource.properties.start_ip_address
}

azure_attribute_absence["db_firewall"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_firewall_rule"
    not resource.properties.end_ip_address
}

azure_issue["db_firewall"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_firewall_rule"
    resource.properties.start_ip_address == "0.0.0.0"
}

azure_issue["db_firewall"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_firewall_rule"
    resource.properties.end_ip_address == "0.0.0.0"
}

db_firewall {
    lower(input.resources[_].type) == "azurerm_sql_firewall_rule"
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

db_firewall_metadata := {
    "Policy Code": "PR-AZR-0082-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "SQL Server Firewall rules allow access to any Azure internal resources",
    "Policy Description": "Firewalls grant access to databases based on the originating IP address of each request and should be within the range of START IP and END IP. Firewall settings with START IP and END IP both with 0.0.0.0 represents access to all Azure internal network. This setting needs to be turned-off to remove blanket access.",
    "Resource Type": "azurerm_sql_firewall_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2015-05-01-preview/servers/firewallrules"
}
