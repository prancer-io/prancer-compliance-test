package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy

# PR-AZR-TRF-SQL-030

default sql_server_alert = null

azure_attribute_absence["sql_server_alert"] {
    count([c | input.resources[_].type == "azurerm_mssql_server_security_alert_policy"; c := 1]) == 0
}

azure_attribute_absence["sql_server_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_security_alert_policy"
    not resource.properties.state
}

azure_issue["sql_server_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
    count([c | r := input.resources[_];
              r.type == "azurerm_mssql_server_security_alert_policy";
              contains(r.properties.server_name, resource.properties.compiletime_identity);
              lower(r.properties.state) == "enabled";
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_mssql_server_security_alert_policy";
              contains(r.properties.server_name, concat(".", [resource.type, resource.name]));
              lower(r.properties.state) == "enabled";
              c := 1]) == 0
}

# azure_issue["sql_server_alert"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_mssql_server_security_alert_policy"
#     lower(resource.properties.state) != "enabled"
# }

sql_server_alert {
    lower(input.resources[_].type) == "azurerm_sql_server"
    not azure_attribute_absence["sql_server_alert"]
    not azure_issue["sql_server_alert"]
}

sql_server_alert = false {
    lower(input.resources[_].type) == "azurerm_sql_server"
    azure_attribute_absence["sql_server_alert"]
}

sql_server_alert = false {
    lower(input.resources[_].type) == "azurerm_sql_server"
    azure_issue["sql_server_alert"]
}

sql_server_alert_err = "Make sure resource azurerm_mssql_server and azurerm_mssql_server_security_alert_policy both exist and property 'state' exist under azurerm_mssql_server_security_alert_policy. Its missing from the resource. Please set the value to 'Enabled' after property 'state' addition." {
    lower(input.resources[_].type) == "azurerm_sql_server"
    azure_attribute_absence["sql_server_alert"]
} else = "Security alert is currently not enabled on SQL Server" {
    lower(input.resources[_].type) == "azurerm_sql_server"
    azure_issue["sql_server_alert"]
}

sql_server_alert_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-030",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Security Alert is enabled on Azure SQL Server",
    "Policy Description": "Advanced data security should be enabled on your SQL servers.",
    "Resource Type": "azurerm_sql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy"
}


# PR-AZR-TRF-SQL-031

default mssql_server_alert = null

azure_attribute_absence["mssql_server_alert"] {
    count([c | input.resources[_].type == "azurerm_mssql_server_security_alert_policy"; c := 1]) == 0
}

azure_attribute_absence["mssql_server_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_security_alert_policy"
    not resource.properties.state
}

azure_issue["mssql_server_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    count([c | r := input.resources[_];
              r.type == "azurerm_mssql_server_security_alert_policy";
              contains(r.properties.server_name, resource.properties.compiletime_identity);
              lower(r.properties.state) == "enabled";
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_mssql_server_security_alert_policy";
              contains(r.properties.server_name, concat(".", [resource.type, resource.name]));
              lower(r.properties.state) == "enabled";
              c := 1]) == 0
}

# azure_issue["mssql_server_alert"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_mssql_server_security_alert_policy"
#     lower(resource.properties.state) != "enabled"
# }

mssql_server_alert {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    not azure_attribute_absence["mssql_server_alert"]
    not azure_issue["mssql_server_alert"]
}

mssql_server_alert = false {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_attribute_absence["mssql_server_alert"]
}

mssql_server_alert = false {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_issue["mssql_server_alert"]
}

mssql_server_alert_err = "Make sure resource azurerm_mssql_server and azurerm_mssql_server_security_alert_policy both exist and property 'state' exist under azurerm_mssql_server_security_alert_policy. Its missing from the resource. Please set the value to 'Enabled' after property 'state' addition." {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_attribute_absence["mssql_server_alert"]
} else = "Security alert is currently not enabled on SQL Server" {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_issue["mssql_server_alert"]
}

mssql_server_alert_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-031",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Security Alert is enabled on Azure SQL Server",
    "Policy Description": "Advanced data security should be enabled on your SQL servers.",
    "Resource Type": "azurerm_mssql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy"
}



