package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/auditingsettings

#
# PR-AZR-0059-ARM
#

default sql_log_retention = null

azure_attribute_absence["sql_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/auditingsettings"
    not resource.properties.state
}

azure_attribute_absence["sql_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/auditingsettings"
    not resource.properties.retentionDays
}

azure_issue["sql_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/auditingsettings"
    lower(resource.properties.state) != "enabled"
}

azure_issue["sql_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/auditingsettings"
    to_number(resource.properties.retentionDays) < 90
    to_number(resource.properties.retentionDays) != 0
}

sql_log_retention {
    lower(input.resources[_].type) == "microsoft.sql/servers/auditingsettings"
    not azure_issue["sql_log_retention"]
    not azure_attribute_absence["sql_log_retention"]
}

sql_log_retention = false {
    azure_issue["sql_log_retention"]
}

sql_log_retention = false {
    azure_attribute_absence["sql_log_retention"]
}

sql_log_retention_err = "Azure SQL Server audit log retention is less than 91 days" {
    azure_issue["sql_log_retention"]
}

sql_log_retention_miss_err = "Auditing settings attribute state/retentionDays missing in the resource" {
    azure_attribute_absence["sql_log_retention"]
}

sql_log_retention_metadata := {
    "Policy Code": "PR-AZR-0059-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure SQL Server audit log retention is less than 91 days",
    "Policy Description": "Audit Logs can help you find suspicious events, unusual activity, and trends. Auditing the SQL server, at the server-level, allows you to track all existing and newly created databases on the instance._x005F_x000D_ _x005F_x000D_ This policy identifies SQL servers which do not retain audit logs for more than 90 days. As a best practice, configure the audit logs retention time period to be greater than 90 days.",
    "Resource Type": "microsoft.sql/servers/auditingsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/auditingsettings"
}


# PR-AZR-0121-ARM

default auditActionsAndGroups = null

azure_issue["auditActionsAndGroups"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/auditingsettings"
    lower(resource.properties.auditActionsAndGroups) == "successful_database_authentication_group"
    lower(resource.properties.auditActionsAndGroups) == "failed_database_authentication_group"
    lower(resource.properties.auditActionsAndGroups) == "batch_completed_group"
}

auditActionsAndGroups {
    azure_issue["auditActionsAndGroups"]
}

auditActionsAndGroups = false {
    lower(input.resources[_].type) == "microsoft.sql/servers/auditingsettings"
    not azure_issue["auditActionsAndGroups"]
}

auditActionsAndGroups_err = "Ensure that 'AuditActionGroups' in 'auditing' policy for a SQL server is set properly" {
    lower(input.resources[_].type) == "microsoft.sql/servers/auditingsettings"
    not azure_issue["auditActionsAndGroups"]
}

auditActionsAndGroups_metadata := {
    "Policy Code": "PR-AZR-0121-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that 'AuditActionGroups' in 'auditing' policy for a SQL server is set properly",
    "Policy Description": "To capture all critical activities done on SQL Servers and databases within sql servers, auditing should be configured to capture appropriate 'AuditActionGroups'. Property `AuditActionGroup` should contains at least `SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP, FAILED_DATABASE_AUTHENTICATION_GROUP, BATCH_COMPLETED_GROUP` to ensure comprehensive audit logging for SQL servers and SQL databases hosted on SQL Server.",
    "Resource Type": "microsoft.sql/servers/auditingsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/administrators"
}
