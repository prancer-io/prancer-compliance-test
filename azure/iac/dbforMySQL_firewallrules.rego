package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformysql/servers/firewallrules

# PR-AZR-ARM-SQL-014

default mysql_ingress_from_any_ip_disabled = null
azure_attribute_absence ["mysql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformysql/servers/firewallrules"
    not resource.properties.startIpAddress
}

azure_attribute_absence ["mysql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformysql/servers/firewallrules"
    not resource.properties.endIpAddress
}

azure_issue ["mysql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformysql/servers/firewallrules"
    contains(resource.properties.startIpAddress, "0.0.0.0")
}

azure_issue ["mysql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformysql/servers/firewallrules"
    contains(resource.properties.endIpAddress, "0.0.0.0")
}

mysql_ingress_from_any_ip_disabled {
    lower(input.resources[_].type) == "microsoft.dbformysql/servers/firewallrules"
    not azure_attribute_absence["mysql_ingress_from_any_ip_disabled"]
    not azure_issue["mysql_ingress_from_any_ip_disabled"]
}

mysql_ingress_from_any_ip_disabled = false {
    azure_issue["mysql_ingress_from_any_ip_disabled"]
}

mysql_ingress_from_any_ip_disabled = false {
    azure_attribute_absence["mysql_ingress_from_any_ip_disabled"]
}


mysql_ingress_from_any_ip_disabled_err = "microsoft.dbformysql/servers/firewallrules property 'startIpAddress' and 'endIpAddress' need to be exist. one or both are missing from the resource." {
    azure_attribute_absence["mysql_ingress_from_any_ip_disabled"]
} else = "MSSQL Database Server currently allowing ingress from all Azure-internal IP addresses" {
    azure_issue["mysql_ingress_from_any_ip_disabled"]
}

mysql_ingress_from_any_ip_disabled_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-014",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "MySQL Database Server should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)",
    "Policy Description": "This policy will identify MySQL Database Server firewall rule that are currently allowing ingress from all Azure-internal IP addresses",
    "Resource Type": "microsoft.dbformysql/servers/firewallrules",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformysql/servers/firewallrules"
}



# PR-AZR-ARM-SQL-015

default my_logical_sql_ingress_from_any_ip_disabled = null
azure_attribute_absence ["my_logical_sql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformysql/servers"
    dbsql_resources := resource.resources[_]
    lower(dbsql_resources.type) == "firewallrules"
    not dbsql_resources.properties.startIpAddress
}

azure_attribute_absence ["my_logical_sql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformysql/servers"
    dbsql_resources := resource.resources[_]
    lower(dbsql_resources.type) == "firewallrules"
    not dbsql_resources.properties.endIpAddress
}

azure_issue ["my_logical_sql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformysql/servers"
    dbsql_resources := resource.resources[_]
    lower(dbsql_resources.type) == "firewallrules"
    contains(dbsql_resources.properties.startIpAddress, "0.0.0.0")
}

azure_issue ["my_logical_sql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformysql/servers"
    dbsql_resources := resource.resources[_]
    lower(dbsql_resources.type) == "firewallrules"
    contains(dbsql_resources.properties.endIpAddress, "0.0.0.0")
}

my_logical_sql_ingress_from_any_ip_disabled {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformysql/servers"
    dbsql_resources := resource.resources[_]
    lower(dbsql_resources.type) == "firewallrules"
    not azure_attribute_absence["my_logical_sql_ingress_from_any_ip_disabled"]
    not azure_issue["my_logical_sql_ingress_from_any_ip_disabled"]
}

my_logical_sql_ingress_from_any_ip_disabled = false {
    azure_issue["my_logical_sql_ingress_from_any_ip_disabled"]
}

my_logical_sql_ingress_from_any_ip_disabled = false {
    azure_attribute_absence["my_logical_sql_ingress_from_any_ip_disabled"]
}


my_logical_sql_ingress_from_any_ip_disabled_err = "microsoft.dbformysql/servers/firewallrules property 'startIpAddress' and 'endIpAddress' need to be exist. one or both are missing from the resource." {
    azure_attribute_absence["my_logical_sql_ingress_from_any_ip_disabled"]
} else = "MSSQL Database Server currently allowing ingress from all Azure-internal IP addresses" {
    azure_issue["my_logical_sql_ingress_from_any_ip_disabled"]
}

my_logical_sql_ingress_from_any_ip_disabled_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-015",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "MySQL Database Server should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)",
    "Policy Description": "This policy will identify MySQL Database Server firewall rule that are currently allowing ingress from all Azure-internal IP addresses",
    "Resource Type": "microsoft.dbformysql/servers/firewallrules",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformysql/servers/firewallrules"
}