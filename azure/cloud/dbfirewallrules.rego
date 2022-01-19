package rule

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2015-05-01-preview/servers/firewallrules

#
# PR-AZR-CLD-SQL-010
# Not valid for cloud provider as cloud seperates all the child resources into seperate resource

# default db_logical_firewall = null

# azure_attribute_absence["db_logical_firewall"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers"
#     sql_db := resource.resources[_]
#     lower(sql_db.type) == "firewallrules"
#     not sql_db.properties.startIpAddress
# }


# azure_attribute_absence["db_logical_firewall"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers"
#     sql_db := resource.resources[_]
#     lower(sql_db.type) == "firewallrules"
#     not sql_db.properties.endIpAddress
# }


# azure_issue["db_logical_firewall"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers"
#     sql_db := resource.resources[_]
#     lower(sql_db.type) == "firewallrules"
#     sql_db.properties.startIpAddress == "0.0.0.0"
# }

# azure_issue["db_logical_firewall"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers"
#     sql_db := resource.resources[_]
#     lower(sql_db.type) == "firewallrules"
#     sql_db.properties.endIpAddress == "0.0.0.0"
# }

# db_logical_firewall {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers"
#     sql_db := resource.resources[_]
#     lower(sql_db.type) == "firewallrules"
#     not azure_attribute_absence["db_logical_firewall"]
#     not azure_issue["db_logical_firewall"]
# }

# db_logical_firewall = false {
#     azure_issue["db_logical_firewall"]
# }

# db_logical_firewall = false {
#     azure_attribute_absence["db_logical_firewall"]
# }

# db_logical_firewall_err = "Firewall rule attribute startIpAddress/endIpAddress is missing from the resource" {
#     azure_attribute_absence["db_logical_firewall"]
# } else = "SQL Server Firewall rule configuration currently allowing full inbound access to everyone" {
#     azure_issue["db_logical_firewall"]
# }


# db_logical_firewall_metadata := {
#     "Policy Code": "PR-AZR-CLD-SQL-010",
#     "Type": "Cloud",
#     "Product": "AZR",
#     "Language": "",
#     "Policy Title": "SQL Server Firewall rules should not configure to allow full inbound access to everyone",
#     "Policy Description": "Firewalls grant access to databases based on the originating IP address of each request and should be within the range of START IP and END IP. Firewall settings with START IP and END IP both with 0.0.0.0 represents access to all Azure internal network. This setting needs to be turned-off to remove blanket access.",
#     "Resource Type": "microsoft.sql/servers/firewallrules",
#     "Policy Help URL": "",
#     "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2015-05-01-preview/servers/firewallrules"
# }

# PR-AZR-CLD-SQL-011
#

default db_firewall = null

azure_attribute_absence["db_firewall"] {
    count([c | lower(input.resources[_].type) == "microsoft.sql/servers/firewallrules"; c := 1]) == 0
}

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
    lower(resource.type) == "microsoft.sql/servers"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.sql/servers/firewallrules";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              not contains(r.properties.startIpAddress, "0.0.0.0");
              not contains(r.properties.endIpAddress, "0.0.0.0");
              c := 1]) == 0
}

db_firewall {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    not azure_attribute_absence["db_firewall"]
    not azure_issue["db_firewall"]
}

db_firewall = false {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_issue["db_firewall"]
}

db_firewall = false {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_attribute_absence["db_firewall"]
}

db_firewall_err = "SQL Server Firewall rule configuration currently allowing full inbound access to everyone" {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_issue["db_firewall"]
} else = "Firewall rule attribute startIpAddress/endIpAddress is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_attribute_absence["db_firewall"]
}

db_firewall_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-011",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "SQL Server Firewall rules should not configure to allow full inbound access to everyone",
    "Policy Description": "Firewalls grant access to databases based on the originating IP address of each request and should be within the range of START IP and END IP. Firewall settings with START IP and END IP both with 0.0.0.0 represents access to all Azure internal network. This setting needs to be turned-off to remove blanket access.",
    "Resource Type": "microsoft.sql/servers/firewallrules",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2015-05-01-preview/servers/firewallrules"
}
