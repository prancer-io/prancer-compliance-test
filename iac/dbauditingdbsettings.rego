package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/auditingsettings

#
# Auditing for SQL database should be set to On (212)
#

default sql_log_audit = null

sql_log_audit {
    lower(input.type) == "microsoft.sql/servers/databases/auditingsettings"
    lower(input.properties.state) == "enabled"
}

sql_log_audit = false {
    lower(input.type) == "microsoft.sql/servers/databases/auditingsettings"
    lower(input.properties.state) != "enabled"
}

sql_log_audit_err = "Auditing for SQL database should be set to On" {
    sql_log_audit == false
}

#
# Azure SQL Database with Auditing Retention less than 90 days (262)
#

default sql_log_retention = null

sql_log_retention {
    lower(input.type) == "microsoft.sql/servers/databases/auditingsettings"
    lower(input.properties.state) == "enabled"
    to_number(input.properties.retentionDays) >= 90
}

sql_log_retention = false {
    lower(input.type) == "microsoft.sql/servers/databases/auditingsettings"
    lower(input.properties.state) != "enabled"
}

sql_log_retention = false {
    lower(input.type) == "microsoft.sql/servers/databases/auditingsettings"
    to_number(input.properties.retentionDays) < 90
}

sql_log_retention_err = "Azure SQL Database with Auditing Retention less than 90 days" {
    sql_log_retention == false
}
