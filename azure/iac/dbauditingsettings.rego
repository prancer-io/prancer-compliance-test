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
    to_number(resource.properties.retentionDays) <= 90
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
