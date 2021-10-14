package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/auditingsettings

#
# PR-AZR-ARM-SQL-004
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
    not azure_attribute_absence["sql_db_log_audit"]
    not azure_issue["sql_db_log_audit"]
}

sql_db_log_audit = false {
    azure_issue["sql_db_log_audit"]
}

sql_db_log_audit = false {
    azure_attribute_absence["sql_db_log_audit"]
}

sql_db_log_audit_err = "Azure SQL Database auditing is currently not enabled" {
    azure_issue["sql_db_log_audit"]
}

sql_db_log_audit_miss_err = "Azure SQL Database Auditing settings attribute 'state' is missing" {
    azure_attribute_absence["sql_db_log_audit"]
}

sql_db_log_audit_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Auditing for SQL database should be enabled",
    "Policy Description": "Database events are tracked by the Auditing feature and the events are written to an audit log in your Azure storage account. This process helps you to monitor database activity, and get insight into anomalies that could indicate business concerns or suspected security violations.",
    "Resource Type": "microsoft.sql/servers/databases/auditingsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/auditingsettings"
}



# PR-AZR-ARM-SQL-005
#

default sql_logical_db_log_audit = null

azure_attribute_absence["sql_logical_db_log_audit"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_db := resource.resources[_]
    lower(sql_db.type) == "auditingsettings"
    not sql_db.properties.state
}

azure_issue["sql_logical_db_log_audit"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_db := resource.resources[_]
    lower(sql_db.type) == "auditingsettings"
    lower(sql_db.properties.state) != "enabled"
}

sql_logical_db_log_audit {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_db := resource.resources[_]
    lower(sql_db.type) == "auditingsettings"
    not azure_attribute_absence["sql_logical_db_log_audit"]
    not azure_issue["sql_logical_db_log_audit"]
}

sql_logical_db_log_audit = false {
    azure_issue["sql_logical_db_log_audit"]
}

sql_logical_db_log_audit = false {
    azure_attribute_absence["sql_logical_db_log_audit"]
}

sql_logical_db_log_audit_err = "Azure SQL Database Auditing settings attribute 'state' is missing" {
    azure_attribute_absence["sql_logical_db_log_audit"]
} else = "Azure SQL Database auditing is currently not enabled" {
    azure_issue["sql_logical_db_log_audit"]
}


sql_logical_db_log_audit_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Auditing for SQL database should be enabled",
    "Policy Description": "Database events are tracked by the Auditing feature and the events are written to an audit log in your Azure storage account. This process helps you to monitor database activity, and get insight into anomalies that could indicate business concerns or suspected security violations.",
    "Resource Type": "microsoft.sql/servers/databases/auditingsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/auditingsettings"
}



#
# PR-AZR-ARM-SQL-006
#

default sql_db_log_retention = null

azure_attribute_absence["sql_db_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/auditingsettings"
    not resource.properties.retentionDays
}

azure_issue["sql_db_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/auditingsettings"
    to_number(resource.properties.retentionDays) < 90
}

sql_db_log_retention {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases/auditingsettings"
    not azure_attribute_absence["sql_db_log_retention"]
    not azure_issue["sql_db_log_retention"]
}

sql_db_log_retention = false {
    azure_issue["sql_db_log_retention"]
}

sql_db_log_retention = false {
    azure_attribute_absence["sql_db_log_retention"]
}

sql_db_log_retention_err = "Azure SQL Database Auditing Retention is currently less than 90 days. It should be 90 days or more" {
    azure_issue["sql_db_log_retention"]
}

sql_db_log_retention_miss_err = "Azure SQL Database Auditing settings attribute 'retentionDays' is missing from the resource" {
    azure_attribute_absence["sql_db_log_retention"]
}

sql_db_log_retention_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure SQL Database Auditing Retention should be 90 days or more",
    "Policy Description": "This policy identifies SQL Databases which have Auditing Retention less than 90 days. Audit Logs can be used to check for anomalies and gives insight into suspected breaches or misuse of information and access. It is recommended to configure SQL database Audit Retention to be greater than or equal to 90 days.",
    "Resource Type": "microsoft.sql/servers/databases/auditingsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/auditingsettings"
}



# PR-AZR-ARM-SQL-007
#

default sql_logical_db_log_retention = null

azure_attribute_absence["sql_logical_db_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_db := resource.resources[_]
    lower(sql_db.type) == "auditingsettings"
    not sql_db.properties.retentionDays
}

azure_issue["sql_logical_db_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_db := resource.resources[_]
    lower(sql_db.type) == "auditingsettings"
    to_number(sql_db.properties.retentionDays) < 90
}

sql_logical_db_log_retention {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_db := resource.resources[_]
    lower(sql_db.type) == "auditingsettings"
    not azure_attribute_absence["sql_logical_db_log_retention"]
    not azure_issue["sql_logical_db_log_retention"]
}

sql_logical_db_log_retention = false {
    azure_issue["sql_logical_db_log_retention"]
}

sql_logical_db_log_retention = false {
    azure_attribute_absence["sql_logical_db_log_retention"]
}

sql_logical_db_log_retention_err = "Azure SQL Database Auditing settings attribute 'retentionDays' is missing from the resource" {
    azure_attribute_absence["sql_logical_db_log_retention"]
} else = "Azure SQL Database Auditing Retention is currently less than 90 days. It should be 90 days or more" {
    azure_issue["sql_logical_db_log_retention"]
}

sql_logical_db_log_retention_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-007",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure SQL Database Auditing Retention should be 90 days or more",
    "Policy Description": "This policy identifies SQL Databases which have Auditing Retention less than 90 days. Audit Logs can be used to check for anomalies and gives insight into suspected breaches or misuse of information and access. It is recommended to configure SQL database Audit Retention to be greater than or equal to 90 days.",
    "Resource Type": "microsoft.sql/servers/databases/auditingsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/auditingsettings"
}
