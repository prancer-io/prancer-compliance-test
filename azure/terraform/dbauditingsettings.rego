package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/auditingsettings
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_extended_auditing_policy
#
# PR-AZR-0059-TRF
#

default mssql_log_retention = null

azure_attribute_absence["mssql_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_extended_auditing_policy"
    not resource.properties.retention_in_days
}

azure_issue["mssql_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_extended_auditing_policy"
    to_number(resource.properties.retention_in_days) < 91
}

mssql_log_retention {
    lower(input.resources[_].type) == "azurerm_mssql_server_extended_auditing_policy"
    not azure_issue["mssql_log_retention"]
    not azure_attribute_absence["mssql_log_retention"]
}

mssql_log_retention = false {
    azure_issue["mssql_log_retention"]
}

mssql_log_retention = false {
    azure_attribute_absence["mssql_log_retention"]
}

mssql_log_retention_err = "Azure SQL Server audit log retention is not greater then 90 days" {
    azure_attribute_absence["mssql_log_retention"]
}

mssql_log_retention_miss_err = "Auditing settings attribute retention_in_days is missing in the resource" {
    azure_attribute_absence["mssql_log_retention"]
}

mssql_log_retention_metadata := {
    "Policy Code": "PR-AZR-0059-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure SQL Server audit log retention should be grater then 90 days",
    "Policy Description": "Audit Logs can help you find suspicious events, unusual activity, and trends. Auditing the SQL server, at the server-level, allows you to track all existing and newly created databases on the instance._x005F_x000D_ _x005F_x000D_ This policy identifies SQL servers which do not retain audit logs for more than 90 days. As a best practice, configure the audit logs retention time period to be greater than 90 days.",
    "Resource Type": "azurerm_mssql_server_extended_auditing_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_extended_auditing_policy"
}
