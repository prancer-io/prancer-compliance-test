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

