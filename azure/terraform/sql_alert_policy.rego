package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy

# PR-AZR-TRF-SQL-031

default sql_server_alert = null

azure_attribute_absence["sql_server_alert"] {
    count([c | input.resources[_].type == "azurerm_mssql_server_security_alert_policy"; c := 1]) == 0
}

azure_attribute_absence["sql_server_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_security_alert_policy"
    not resource.properties.state
}

azure_sql_security_alert_disabled["sql_server_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_security_alert_policy"
    lower(resource.properties.state) == "disabled"
}

sql_server_alert {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    not azure_attribute_absence["sql_server_alert"]
    not azure_sql_security_alert_disabled["sql_server_alert"]
}

sql_server_alert = false {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_attribute_absence["sql_server_alert"]
}

sql_server_alert = false {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_sql_security_alert_disabled["sql_server_alert"]
}

sql_server_alert_err = "Make sure resource azurerm_mssql_server and azurerm_mssql_server_security_alert_policy both exist and property 'state' exist under azurerm_mssql_server_security_alert_policy. Its missing from the resource. Please set the value to 'Enabled' after property 'state' addition." {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_attribute_absence["sql_server_alert"]
} else = "Security alert is currently not enabled on SQL Server" {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_sql_security_alert_disabled["sql_server_alert"]
}

sql_server_alert_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-031",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Security Alert is enabled on Azure SQL Server",
    "Policy Description": "Advanced data security should be enabled on your SQL servers.",
    "Resource Type": "azurerm_mssql_server_security_alert_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy"
}
