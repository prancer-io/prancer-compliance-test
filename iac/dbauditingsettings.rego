package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/auditingsettings

#
# Azure SQL Server audit log retention is less than 91 days (268)
#

default sql_log_retention = null

sql_log_retention {
    lower(input.type) == "microsoft.sql/servers/auditingsettings"
    lower(input.properties.state) == "enabled"
    to_number(input.properties.retentionDays) > 90
}

sql_log_retention = false {
    lower(input.type) == "microsoft.sql/servers/auditingsettings"
    lower(input.properties.state) != "enabled"
}

sql_log_retention = false {
    lower(input.type) == "microsoft.sql/servers/auditingsettings"
    to_number(input.properties.retentionDays) <= 90
}

sql_log_retention_err = "Azure SQL Server audit log retention is less than 91 days" {
    sql_log_retention == false
}
