package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/auditingsettings

#
# PR-AZR-0003-TRF
#

default mssql_db_log_audit = null

azure_attribute_absence["mssql_db_log_audit"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_database"
    count([c | input.resources[_].type == "azurerm_mssql_database_extended_auditing_policy"; 
           c := 1]) == 0
}

azure_issue["mssql_db_log_audit"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_database"
    count([c | r := input.resources[_];
               r.type == "azurerm_mssql_database_extended_auditing_policy";
               re_match(concat("", ["^.*\\.", resource.name, "\\..*$"]), r.properties.database_id);
               c := 1]) == 0
    true == false # workaround for inconsistent resource naming
}

mssql_db_log_audit {
    lower(input.resources[_].type) == "azurerm_mssql_database_extended_auditing_policy"
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

mssql_db_log_audit_metadata := {
    "Policy Code": "PR-AZR-0003-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Auditing for SQL database should be set to On",
    "Policy Description": "Database events are tracked by the Auditing feature and the events are written to an audit log in your Azure storage account. This process helps you to monitor database activity, and get insight into anomalies that could indicate business concerns or suspected security violations.",
    "Resource Type": "azurerm_mssql_database_extended_auditing_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/auditingsettings"
}

#
# PR-AZR-0053-TRF
#

default mssql_db_log_retention = null

azure_attribute_absence["mssql_db_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_database_extended_auditing_policy"
    not resource.properties.retention_in_days
}

azure_issue["mssql_db_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_database_extended_auditing_policy"
    to_number(resource.properties.retention_in_days) < 90
}

mssql_db_log_retention {
    lower(input.resources[_].type) == "azurerm_mssql_database_extended_auditing_policy"
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

mssql_db_log_retention_metadata := {
    "Policy Code": "PR-AZR-0053-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure SQL Database with Auditing Retention less than 90 days",
    "Policy Description": "This policy identifies SQL Databases which have Auditing Retention less than 90 days. Audit Logs can be used to check for anomalies and gives insight into suspected breaches or misuse of information and access. It is recommended to configure SQL database Audit Retention to be greater than or equal to 90 days.",
    "Resource Type": "azurerm_mssql_database_extended_auditing_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/auditingsettings"
}
