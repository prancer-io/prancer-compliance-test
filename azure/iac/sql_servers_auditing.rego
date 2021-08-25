package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2021-02-01-preview/servers/auditingsettings

#
# PR-AZR-0134-ARM
#

default sql_server_log_audit = null

azure_attribute_absence["sql_server_log_audit"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/auditingsettings"
    not resource.properties.state
}

azure_issue["sql_server_log_audit"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/auditingsettings"
    lower(resource.properties.state) != "enabled"
}

sql_server_log_audit {
    lower(input.resources[_].type) == "microsoft.sql/servers/auditingsettings"
    not azure_attribute_absence["sql_server_log_audit"]
    not azure_issue["sql_server_log_audit"]
}

sql_server_log_audit = false {
    azure_issue["sql_server_log_audit"]
}

sql_server_log_audit = false {
    azure_attribute_absence["sql_server_log_audit"]
}

sql_server_log_audit_err = "Azure SQL Server auditing is currently not enabled" {
    azure_issue["sql_server_log_audit"]
}

sql_server_log_audit_miss_err = "Azure SQL Server Auditing settings attribute 'state' is missing" {
    azure_attribute_absence["sql_server_log_audit"]
}

sql_server_log_audit_metadata := {
    "Policy Code": "PR-AZR-0134-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that SQL Server Auditing is Enabled",
    "Policy Description": "Ensure that SQL Server Auditing is enabled in order to keep track of Audit events.",
    "Resource Type": "Microsoft.Sql/servers/auditingSettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2021-02-01-preview/servers/auditingsettings"
}





# PR-AZR-0135-ARM
#

default sql_logical_server_log_audit = null

azure_attribute_absence["sql_logical_server_log_audit"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "auditingsettings"
    not sql_resources.properties.state
}

azure_issue["sql_logical_server_log_audit"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "auditingsettings"
    lower(sql_resources.properties.state) != "enabled"
}

sql_logical_server_log_audit {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    resource := input.resources[_]
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "auditingsettings"
    not azure_attribute_absence["sql_logical_server_log_audit"]
    not azure_issue["sql_logical_server_log_audit"]
}

sql_logical_server_log_audit = false {
    azure_issue["sql_logical_server_log_audit"]
}

sql_logical_server_log_audit = false {
    azure_attribute_absence["sql_logical_server_log_audit"]
}

sql_logical_server_log_audit_err = "Azure SQL Server auditing is currently not enabled" {
    azure_issue["sql_logical_server_log_audit"]
}

sql_logical_server_log_audit_miss_err = "Azure SQL Server Auditing settings attribute 'state' is missing" {
    azure_attribute_absence["sql_logical_server_log_audit"]
}

sql_logical_server_log_audit_metadata := {
    "Policy Code": "PR-AZR-0135-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that SQL Server Auditing is Enabled",
    "Policy Description": "Ensure that SQL Server Auditing is enabled in order to keep track of Audit events.",
    "Resource Type": "Microsoft.Sql/servers/auditingSettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2021-02-01-preview/servers/auditingsettings"
}




# PR-AZR-0145-ARM
#

default sql_server_audit_log_retention = null


azure_attribute_absence["sql_server_audit_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/auditingsettings"
    not resource.properties.retentionDays
}

azure_issue["sql_server_audit_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/auditingsettings"
    to_number(resource.properties.retentionDays) < 91
}

sql_server_audit_log_retention {
    lower(input.resources[_].type) == "microsoft.sql/servers/auditingsettings"
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
    "Policy Code": "PR-AZR-0145-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure SQL server audit log retention should be greater than 90 days",
    "Policy Description": "Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access. We recommend you configure SQL server audit retention to be greater than 90 days.",
    "Resource Type": "Microsoft.Sql/servers/auditingSettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2021-02-01-preview/servers/auditingsettings"
}



# PR-AZR-0146-ARM
#

default sql_logial_server_audit_log_retention = null


azure_attribute_absence["sql_logial_server_audit_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "auditingsettings"
    not sql_resources.properties.retentionDays
}

azure_issue["sql_logial_server_audit_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "auditingsettings"
    to_number(sql_resources.properties.retentionDays) < 91
}

sql_logial_server_audit_log_retention {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    resource := input.resources[_]
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "auditingsettings"
    not azure_attribute_absence["sql_logial_server_audit_log_retention"]
    not azure_issue["sql_logial_server_audit_log_retention"]
}

sql_logial_server_audit_log_retention = false {
    azure_issue["sql_logial_server_audit_log_retention"]
}

sql_logial_server_audit_log_retention = false {
    azure_attribute_absence["sql_logial_server_audit_log_retention"]
}

sql_logial_server_audit_log_retention_err = "microsoft.sql/servers/auditingsettings resource property retentionDays missing in the resource" {
    azure_attribute_absence["sql_logial_server_audit_log_retention"]
} else = "Azure SQL server audit log retention is less than 91 days" {
    azure_issue["sql_logial_server_audit_log_retention"]
}


sql_logial_server_audit_log_retention_metadata := {
    "Policy Code": "PR-AZR-0146-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure SQL server audit log retention should be greater than 90 days",
    "Policy Description": "Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access. We recommend you configure SQL server audit retention to be greater than 90 days.",
    "Resource Type": "Microsoft.Sql/servers/auditingSettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2021-02-01-preview/servers/auditingsettings"
}

