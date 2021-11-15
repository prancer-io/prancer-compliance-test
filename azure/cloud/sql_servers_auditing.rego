package rule

# https://docs.microsoft.com/en-us/rest/api/sql/2017-03-01-preview/server-auditing-settings/get

#
# PR-AZR-SQL-042
#

default sql_server_log_audit = null

azure_attribute_absence["sql_server_log_audit"] {
    not input.properties.state
}

azure_issue["sql_server_log_audit"] {
    lower(input.properties.state) != "enabled"
}

sql_server_log_audit {
    not azure_attribute_absence["sql_server_log_audit"]
    not azure_issue["sql_server_log_audit"]
}

sql_server_log_audit = false {
    azure_issue["sql_server_log_audit"]
}

sql_server_log_audit = false {
    azure_attribute_absence["sql_server_log_audit"]
}

sql_server_log_audit_err = "Azure SQL Server Auditing settings attribute 'state' is missing" {
    azure_attribute_absence["sql_server_log_audit"]
} else = "Azure SQL Server auditing is currently not enabled" {
    azure_issue["sql_server_log_audit"]
}


sql_server_log_audit_metadata := {
    "Policy Code": "PR-AZR-SQL-042",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure that SQL Server Auditing is Enabled",
    "Policy Description": "Ensure that SQL Server Auditing is enabled in order to keep track of Audit events.",
    "Resource Type": "Microsoft.Sql/servers/auditingSettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/sql/2017-03-01-preview/server-auditing-settings/get"
}


# PR-AZR-SQL-044
#

default sql_server_audit_log_retention = null


azure_attribute_absence["sql_server_audit_log_retention"] {
    not input.properties.retentionDays
}


azure_issue["sql_server_audit_log_retention"] {
    to_number(input.properties.retentionDays) < 91
}

sql_server_audit_log_retention {
    not azure_attribute_absence["sql_server_audit_log_retention"]
    not azure_issue["sql_server_audit_log_retention"]
}

sql_server_audit_log_retention = false {
    azure_issue["sql_server_audit_log_retention"]
}

sql_server_audit_log_retention = false {
    azure_attribute_absence["sql_server_audit_log_retention"]
}

sql_server_audit_log_retention_err = "microsoft.sql/servers/auditingsettings resource property retentionDays missing in the resource" {
    azure_attribute_absence["sql_server_audit_log_retention"]
} else = "Azure SQL server audit log retention is less than 91 days" {
    azure_issue["sql_server_audit_log_retention"]
}


sql_server_audit_log_retention_metadata := {
    "Policy Code": "PR-AZR-SQL-044",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure SQL server audit log retention should be greater than 90 days",
    "Policy Description": "Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access. We recommend you configure SQL server audit retention to be greater than 90 days.",
    "Resource Type": "Microsoft.Sql/servers/auditingSettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/sql/2017-03-01-preview/server-auditing-settings/get"
}