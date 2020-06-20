package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/auditingsettings

#
# Azure SQL Server audit log retention is less than 91 days (268)
#

default sql_log_retention = null

sql_log_retention {
    input.type == "Microsoft.Sql/servers/auditingSettings"
    lower(input.properties.state) == "enabled"
    to_number(input.properties.retentionDays) > 90
}

sql_log_retention = false {
    input.type == "Microsoft.Sql/servers/auditingSettings"
    lower(input.properties.state) != "enabled"
}

sql_log_retention = false {
    input.type == "Microsoft.Sql/servers/auditingSettings"
    to_number(input.properties.retentionDays) <= 90
}

sql_log_retention_err = "Azure SQL Server audit log retention is less than 91 days" {
    sql_log_retention == false
}
