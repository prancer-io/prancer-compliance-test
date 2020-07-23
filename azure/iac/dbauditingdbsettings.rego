package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/auditingsettings

#
# Auditing for SQL database should be set to On (212)
#

default sql_db_log_audit = null

azure_attribute_absence["sql_db_log_audit"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/auditingsettings"
    not resource.properties.state
}

azure_issue["sql_db_log_audit"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/auditingsettings"
    lower(resource.properties.state) != "enabled"
}

sql_db_log_audit {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases/auditingsettings"
    not azure_issue["sql_db_log_audit"]
    not azure_attribute_absence["sql_db_log_audit"]
}

sql_db_log_audit = false {
    azure_issue["sql_db_log_audit"]
}

sql_db_log_audit = false {
    azure_attribute_absence["sql_db_log_audit"]
}

sql_db_log_audit_err = "Azure SQL Database with Auditing Retention less than 90 days" {
    azure_issue["sql_db_log_audit"]
}

sql_db_log_audit_miss_err = "Auditing for SQL database should be set to On" {
    azure_attribute_absence["sql_db_log_audit"]
}

#
# Azure SQL Database with Auditing Retention less than 90 days (262)
#

default sql_db_log_retention = null

azure_attribute_absence["sql_db_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/auditingsettings"
    not resource.properties.state
}

azure_attribute_absence["sql_db_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/auditingsettings"
    not resource.properties.retentionDays
}

azure_issue["sql_db_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/auditingsettings"
    lower(resource.properties.state) != "enabled"
}

azure_issue["sql_db_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/auditingsettings"
    to_number(resource.properties.retentionDays) < 90
}

sql_db_log_retention {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases/auditingsettings"
    not azure_issue["sql_db_log_retention"]
    not azure_attribute_absence["sql_db_log_retention"]
}

sql_db_log_retention = false {
    azure_issue["sql_db_log_retention"]
}

sql_db_log_retention = false {
    azure_attribute_absence["sql_db_log_retention"]
}

sql_db_log_retention_err = "Azure SQL Database with Auditing Retention less than 90 days" {
    azure_issue["sql_db_log_retention"]
}

sql_db_log_retention_miss_err = "Auditing settings attribute state/retentionDays missing in the resource" {
    azure_attribute_absence["sql_db_log_retention"]
}
