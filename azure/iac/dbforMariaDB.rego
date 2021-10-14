package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformariadb/2018-06-01/servers/firewallrules

# PR-AZR-ARM-SQL-012

default maria_ingress_from_any_ip_disabled = null
azure_attribute_absence ["maria_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers/firewallrules"
    not resource.properties.startIpAddress
}

azure_attribute_absence ["maria_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers/firewallrules"
    not resource.properties.endIpAddress
}

azure_issue ["maria_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers/firewallrules"
    contains(resource.properties.startIpAddress, "0.0.0.0")
}

azure_issue ["maria_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers/firewallrules"
    contains(resource.properties.endIpAddress, "0.0.0.0")
}

maria_ingress_from_any_ip_disabled {
    lower(input.resources[_].type) == "microsoft.dbformariadb/servers/firewallrules"
    not azure_attribute_absence["maria_ingress_from_any_ip_disabled"]
    not azure_issue["maria_ingress_from_any_ip_disabled"]
}

maria_ingress_from_any_ip_disabled = false {
    azure_issue["maria_ingress_from_any_ip_disabled"]
}

maria_ingress_from_any_ip_disabled = false {
    azure_attribute_absence["maria_ingress_from_any_ip_disabled"]
}


maria_ingress_from_any_ip_disabled_err = "Microsoft.DBforMariaDB/servers/firewallRules property 'startIpAddress' and 'endIpAddress' need to be exist. one or both are missing from the resource." {
    azure_attribute_absence["maria_ingress_from_any_ip_disabled"]
} else = "MariaDB currently allowing ingress from all Azure-internal IP addresses" {
    azure_issue["maria_ingress_from_any_ip_disabled"]
}

maria_ingress_from_any_ip_disabled_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-012",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "MariaDB should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)",
    "Policy Description": "This policy will identify MariaDB firewall rule that are currently allowing ingress from all Azure-internal IP addresses",
    "Resource Type": "microsoft.dbformariadb/servers/firewallrules",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformariadb/2018-06-01/servers/firewallrules"
}




# PR-AZR-ARM-SQL-013

default dbmaria_ingress_from_any_ip_disabled = null
azure_attribute_absence ["dbmaria_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers"
    dbsql_resources := resource.resources[_]
    lower(dbsql_resources.type) == "firewallrules"
    not dbsql_resources.properties.startIpAddress
}

azure_attribute_absence ["dbmaria_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers"
    dbsql_resources := resource.resources[_]
    lower(dbsql_resources.type) == "firewallrules"
    not dbsql_resources.properties.endIpAddress
}

azure_issue ["dbmaria_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers"
    dbsql_resources := resource.resources[_]
    lower(dbsql_resources.type) == "firewallrules"
    contains(dbsql_resources.properties.startIpAddress, "0.0.0.0")
}

azure_issue ["dbmaria_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers"
    dbsql_resources := resource.resources[_]
    lower(dbsql_resources.type) == "firewallrules"
    contains(dbsql_resources.properties.endIpAddress, "0.0.0.0")
}

dbmaria_ingress_from_any_ip_disabled {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers"
    dbsql_resources := resource.resources[_]
    lower(dbsql_resources.type) == "firewallrules"
    not azure_attribute_absence["dbmaria_ingress_from_any_ip_disabled"]
    not azure_issue["dbmaria_ingress_from_any_ip_disabled"]
}

dbmaria_ingress_from_any_ip_disabled = false {
    azure_issue["dbmaria_ingress_from_any_ip_disabled"]
}

dbmaria_ingress_from_any_ip_disabled = false {
    azure_attribute_absence["dbmaria_ingress_from_any_ip_disabled"]
}


dbmaria_ingress_from_any_ip_disabled_err = "microsoft.dbformariadb/servers/firewallrules property 'startIpAddress' and 'endIpAddress' need to be exist. one or both are missing from the resource." {
    azure_attribute_absence["dbmaria_ingress_from_any_ip_disabled"]
} else = "MariaDB currently allowing ingress from all Azure-internal IP addresses" {
    azure_issue["dbmaria_ingress_from_any_ip_disabled"]
}

dbmaria_ingress_from_any_ip_disabled_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-013",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "MariaDB should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)",
    "Policy Description": "This policy will identify MariaDB firewall rule that are currently allowing ingress from all Azure-internal IP addresses",
    "Resource Type": "microsoft.dbformariadb/servers/firewallrules",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformariadb/servers/firewallrules"
}