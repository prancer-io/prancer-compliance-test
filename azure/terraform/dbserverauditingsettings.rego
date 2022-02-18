package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/auditingsettings
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_extended_auditing_policy
#
# PR-AZR-TRF-SQL-044
#

default mssql_log_retention = null

azure_attribute_absence["mssql_log_retention"] {
    count([c | input.resources[_].type == "azurerm_mssql_server_extended_auditing_policy"; c := 1]) == 0
}

azure_attribute_absence["mssql_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_extended_auditing_policy"
    not resource.properties.retention_in_days
}

azure_issue["mssql_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    count([c | r := input.resources[_];
              r.type == "azurerm_mssql_server_extended_auditing_policy";
              contains(r.properties.server_id, resource.properties.compiletime_identity);
              to_number(r.properties.retention_in_days) > 0;
              to_number(r.properties.retention_in_days) < 90;
              c := 1]) > 0
    count([c | r := input.resources[_];
              r.type == "azurerm_mssql_server_extended_auditing_policy";
              contains(r.properties.server_id, concat(".", [resource.type, resource.name]));
              to_number(r.properties.retention_in_days) > 0;
              to_number(r.properties.retention_in_days) < 90;
              c := 1]) > 0
}

azure_issue["mssql_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    count([c | r := input.resources[_];
              r.type == "azurerm_mssql_server_extended_auditing_policy";
              contains(r.properties.server_id, resource.properties.compiletime_identity);
              to_number(r.properties.retention_in_days) < 0;
              c := 1]) > 0
    count([c | r := input.resources[_];
              r.type == "azurerm_mssql_server_extended_auditing_policy";
              contains(r.properties.server_id, concat(".", [resource.type, resource.name]));
              to_number(r.properties.retention_in_days) < 0;
              c := 1]) > 0
}

# azure_issue["mssql_log_retention"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_mssql_server_extended_auditing_policy"
#     to_number(resource.properties.retention_in_days) < 91
# }

mssql_log_retention {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    not azure_attribute_absence["mssql_log_retention"]
    not azure_issue["mssql_log_retention"]
}

mssql_log_retention = false {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_attribute_absence["mssql_log_retention"]
}

mssql_log_retention = false {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_issue["mssql_log_retention"]
}

mssql_log_retention_err = "azurerm_mssql_server_extended_auditing_policy resource is missing or its property 'retention_in_days' is missing" {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_attribute_absence["mssql_log_retention"]
} else = "Azure MSSQL Server audit log retention is not equal or greater then 90 days" {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_attribute_absence["mssql_log_retention"]
}

mssql_log_retention_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-044",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure MSSQL Server audit log retention should be equal or greater then 90 days",
    "Policy Description": "Audit Logs can help you find suspicious events, unusual activity, and trends. Auditing the SQL server, at the server-level, allows you to track all existing and newly created databases on the instance.<br><br>This policy identifies SQL servers which do not retain audit logs for 90 days or more. As a best practice, configure the audit logs retention time period to be equal or greater than 90 days.",
    "Resource Type": "azurerm_mssql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_extended_auditing_policy"
}


#
# PR-AZR-TRF-SQL-045
#

default sql_log_retention = null

azure_attribute_absence["sql_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
    not resource.properties.extended_auditing_policy
}

azure_attribute_absence["sql_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
    extended_auditing_policy := resource.properties.extended_auditing_policy[_]
    not extended_auditing_policy.retention_in_days
}

azure_issue["mssql_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
    extended_auditing_policy := resource.properties.extended_auditing_policy[_]
    to_number(extended_auditing_policy.retention_in_days) > 0
    to_number(extended_auditing_policy.retention_in_days) < 90
}

azure_issue["mssql_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
    extended_auditing_policy := resource.properties.extended_auditing_policy[_]
    to_number(extended_auditing_policy.retention_in_days) < 0
}

sql_log_retention {
    lower(input.resources[_].type) == "azurerm_sql_server"
    not azure_attribute_absence["sql_log_retention"]
    not azure_issue["sql_log_retention"]
}

sql_log_retention = false {
    azure_attribute_absence["sql_log_retention"]
}

sql_log_retention = false {
    azure_issue["sql_log_retention"]
}

sql_log_retention_err = "azurerm_sql_server's resource block 'extended_auditing_policy' is missing or its property 'retention_in_days' is missing" {
    azure_attribute_absence["sql_log_retention"]
} else = "Azure SQL Server audit log retention is not equal or greater then 90 days" {
    azure_attribute_absence["sql_log_retention"]
}

sql_log_retention_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-045",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure SQL Server audit log retention should be 90 days or more",
    "Policy Description": "Audit Logs can help you find suspicious events, unusual activity, and trends. Auditing the SQL server, at the server-level, allows you to track all existing and newly created databases on the instance.<br><br>This policy identifies SQL servers which do not retain audit logs for 90 days or more. As a best practice, configure the audit logs retention time period to be equal or greater than 90 days.",
    "Resource Type": "azurerm_sql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server
#
# PR-AZR-TRF-SQL-054
#

default mssql_auditing_enabled = null

azure_attribute_absence["mssql_auditing_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    not resource.properties.extended_auditing_policy
}

mssql_auditing_enabled = false {
    azure_attribute_absence["mssql_auditing_enabled"]
} 

mssql_auditing_enabled {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    not azure_attribute_absence["mssql_auditing_enabled"]
}

mssql_auditing_enabled_err = "Azure MSSQL Server audit log is currently not enabled" {
    azure_attribute_absence["mssql_auditing_enabled"]
}

mssql_auditing_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-054",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure MSSQL Server audit log should be enabled",
    "Policy Description": "Audit Logs can help you find suspicious events, unusual activity, and trends. Auditing the SQL server, at the server-level, allows you to track all existing and newly created databases on the instance.<br><br>This policy identifies SQL servers which do not have audit log enabled.",
    "Resource Type": "azurerm_mssql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server
#
# PR-AZR-TRF-SQL-055
#
# This resource provides usage of Microsoft SQL Azure Database server using an older sku based model. 
# It is recommended going forward to use azurerm_mssql_server resource which provides support for vcores
default sql_auditing_enabled = null

azure_attribute_absence["sql_auditing_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
    not resource.properties.extended_auditing_policy
}

sql_auditing_enabled = false {
    azure_attribute_absence["sql_auditing_enabled"]
} 

sql_auditing_enabled {
    lower(input.resources[_].type) == "azurerm_sql_server"
    not azure_attribute_absence["sql_auditing_enabled"]
}

sql_auditing_enabled_err = "Azure SQL Server audit log is currently not enabled" {
    azure_attribute_absence["sql_auditing_enabled"]
}

sql_auditing_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-055",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure SQL Server audit log should be enabled",
    "Policy Description": "Audit Logs can help you find suspicious events, unusual activity, and trends. Auditing the SQL server, at the server-level, allows you to track all existing and newly created databases on the instance.<br><br>This policy identifies SQL servers which do not have audit log enabled.",
    "Resource Type": "azurerm_sql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server"
}
