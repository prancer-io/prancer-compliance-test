package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/auditingsettings

#
# Azure SQL Server audit log retention is less than 91 days (268)
#

default mssql_log_retention = null

azure_attribute_absence["mssql_log_retention"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_mssql_server_extended_auditing_policy"
    not resource.properties.retention_in_days
}

azure_issue["mssql_log_retention"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_mssql_server_extended_auditing_policy"
    to_number(resource.properties.retention_in_days) < 91
}

mssql_log_retention {
    lower(input.json.resources[_].type) == "azurerm_mssql_server_extended_auditing_policy"
    not azure_issue["mssql_log_retention"]
    not azure_attribute_absence["mssql_log_retention"]
}

mssql_log_retention = false {
    azure_issue["mssql_log_retention"]
}

mssql_log_retention = false {
    azure_attribute_absence["mssql_log_retention"]
}

mssql_log_retention_err = "Azure SQL Server audit log retention is less than 91 days"
}

mssql_log_retention_miss_err = "Auditing settings attribute retention_in_days missing in the resource" {
    azure_attribute_absence["mssql_log_retention"]
}
