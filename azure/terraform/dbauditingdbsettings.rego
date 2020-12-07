package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/auditingsettings

#
# Auditing for SQL database should be set to On (212)
#

default mssql_db_log_audit = null

azure_attribute_absence["mssql_db_log_audit"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_mssql_database"
    count([c | input.json.resources[_].type == "azurerm_mssql_database_extended_auditing_policy"; 
           c := 1]) == 0
}

azure_issue["mssql_db_log_audit"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_mssql_database"
    count([c | r := input.json.resources[_];
               r.type == "azurerm_mssql_database_extended_auditing_policy";
               re_match(concat("", ["^.*\\.", resource.name, "\\..*$"]), r.properties.database_id);
               c := 1]) == 0
    true == false # workaround for inconsistent resource naming
}

mssql_db_log_audit {
    lower(input.json.resources[_].type) == "azurerm_mssql_database_extended_auditing_policy"
    not azure_issue["mssql_db_log_audit"]
    not azure_attribute_absence["mssql_db_log_audit"]
}

mssql_db_log_audit = false {
    azure_issue["mssql_db_log_audit"]
}

mssql_db_log_audit = false {
    azure_attribute_absence["mssql_db_log_audit"]
}

mssql_db_log_audit_err = "Auditing for SQL database should be set to On" {
    azure_issue["mssql_db_log_audit"]
}

mssql_db_log_audit_miss_err = "Auditing for SQL database should be set to On" {
    azure_attribute_absence["mssql_db_log_audit"]
}

#
# Azure SQL Database with Auditing Retention less than 90 days (262)
#

default mssql_db_log_retention = null

azure_attribute_absence["mssql_db_log_retention"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_mssql_database_extended_auditing_policy"
    not resource.properties.retention_in_days
}

azure_issue["mssql_db_log_retention"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_mssql_database_extended_auditing_policy"
    to_number(resource.properties.retention_in_days) < 90
}

mssql_db_log_retention {
    lower(input.json.resources[_].type) == "azurerm_mssql_database_extended_auditing_policy"
    not azure_issue["mssql_db_log_retention"]
    not azure_attribute_absence["mssql_db_log_retention"]
}

mssql_db_log_retention = false {
    azure_issue["mssql_db_log_retention"]
}

mssql_db_log_retention = false {
    azure_attribute_absence["mssql_db_log_retention"]
}

mssql_db_log_retention_err = "Azure SQL Database with Auditing Retention less than 90 days" {
    azure_issue["mssql_db_log_retention"]
}

mssql_db_log_retention_miss_err = "Auditing settings attribute retention_in_days missing in the resource" {
    azure_attribute_absence["mssql_db_log_retention"]
}
