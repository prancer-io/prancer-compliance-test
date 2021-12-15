package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/auditingsettings
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_database_extended_auditing_policy

#
# PR-AZR-TRF-SQL-004
#

default mssql_db_log_audit = null

#azure_attribute_absence["mssql_db_log_audit"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_mssql_database"
#    count([c | input.resources[_].type == "azurerm_mssql_database_extended_auditing_policy"; 
#           c := 1]) == 0
#}

#azure_issue["mssql_db_log_audit"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_mssql_database"
#    count([c | r := input.resources[_];
#               r.type == "azurerm_mssql_database_extended_auditing_policy";
#               re_match(concat("", ["^.*\\.", resource.name, "\\..*$"]), r.properties.database_id); # Rezoan: this regex is not correct and need a fix. Snapshot file does not generate database_id out of the tf variable as well at r.properties.database_id
#               c := 1]) == 0
#    true == false # workaround for inconsistent resource naming
#}

azure_attribute_absence ["mssql_db_log_audit"] {
    count([c | input.resources[_].type == "azurerm_mssql_database_extended_auditing_policy"; c := 1]) == 0
}

azure_issue["mssql_db_log_audit"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_database"
    count([c | r := input.resources[_];
              r.type == "azurerm_mssql_database_extended_auditing_policy";
              contains(r.properties.database_id, resource.properties.compiletime_identity);
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_mssql_database_extended_auditing_policy";
              contains(r.properties.database_id, concat(".", [resource.type, resource.name]));
              c := 1]) == 0
}

mssql_db_log_audit {
    lower(input.resources[_].type) == "azurerm_mssql_database"
    not azure_attribute_absence["mssql_db_log_audit"]
    not azure_issue["mssql_db_log_audit"]
}

mssql_db_log_audit = false {
    lower(input.resources[_].type) == "azurerm_mssql_database"
    azure_attribute_absence["mssql_db_log_audit"]
}

mssql_db_log_audit = false {
    lower(input.resources[_].type) == "azurerm_mssql_database"
    azure_issue["mssql_db_log_audit"]
}

mssql_db_log_audit_err = "azurerm_mssql_database_extended_auditing_policy resource is missing from template or its not linked with target azurerm_mssql_database" {
    lower(input.resources[_].type) == "azurerm_mssql_database"
    azure_attribute_absence["mssql_db_log_audit"]
} else = "Auditing for SQL database is not enabled" {
    lower(input.resources[_].type) == "azurerm_mssql_database"
    azure_issue["mssql_db_log_audit"]
}

mssql_db_log_audit_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Auditing for SQL database should be enabled",
    "Policy Description": "Database events are tracked by the Auditing feature and the events are written to an audit log in your Azure storage account. This process helps you to monitor database activity, and get insight into anomalies that could indicate business concerns or suspected security violations.",
    "Resource Type": "azurerm_mssql_database",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_database_extended_auditing_policy"
}

#
# PR-AZR-TRF-SQL-005
#

default mssql_db_log_retention = null

azure_attribute_absence ["mssql_db_log_retention"] {
    count([c | input.resources[_].type == "azurerm_mssql_database_extended_auditing_policy"; c := 1]) == 0
}

azure_attribute_absence["mssql_db_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_database_extended_auditing_policy"
    not resource.properties.retention_in_days
}

azure_issue["mssql_db_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_database"
    count([c | r := input.resources[_];
              r.type == "azurerm_mssql_database_extended_auditing_policy";
              contains(r.properties.database_id, resource.properties.compiletime_identity);
              to_number(resource.properties.retention_in_days) >= 90
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_mssql_database_extended_auditing_policy";
              contains(r.properties.database_id, concat(".", [resource.type, resource.name]));
              to_number(resource.properties.retention_in_days) >= 90
              c := 1]) == 0
}

# azure_issue["mssql_db_log_retention"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_mssql_database_extended_auditing_policy"
#     to_number(resource.properties.retention_in_days) < 90
# }

mssql_db_log_retention {
    lower(input.resources[_].type) == "azurerm_mssql_database"
    not azure_attribute_absence["mssql_db_log_retention"]
    not azure_issue["mssql_db_log_retention"]
}

mssql_db_log_retention = false {
    lower(input.resources[_].type) == "azurerm_mssql_database"
    azure_attribute_absence["mssql_db_log_retention"]
}

mssql_db_log_retention = false {
    lower(input.resources[_].type) == "azurerm_mssql_database"
    azure_issue["mssql_db_log_retention"]
}

mssql_db_log_retention_err = "azurerm_mssql_database_extended_auditing_policy resource is missing or its property 'retention_in_days' is missing" {
    lower(input.resources[_].type) == "azurerm_mssql_database"
    azure_attribute_absence["mssql_db_log_retention"]
} else = "Azure SQL Database with Auditing Retention is not equal or more then 90 days" {
    lower(input.resources[_].type) == "azurerm_mssql_database"
    azure_issue["mssql_db_log_retention"]
}

mssql_db_log_retention_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Azure SQL Database Auditing Retention is minimum 90 days or more",
    "Policy Description": "This policy identifies SQL Databases which have Auditing Retention less than 90 days. Audit Logs can be used to check for anomalies and gives insight into suspected breaches or misuse of information and access. It is recommended to configure SQL database Audit Retention to be greater than or equal to 90 days.",
    "Resource Type": "azurerm_mssql_database",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_database_extended_auditing_policy"
}
