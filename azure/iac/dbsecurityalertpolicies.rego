package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies

#
# Azure SQL DB with Threat Retention less than 91 days (263)
#

default dbsec_threat_retention = null

dbsec_threat_retention {
    lower(input.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    lower(input.properties.state) == "enabled"
    input.properties.retentionDays > 90
}

dbsec_threat_retention = false {
    lower(input.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    lower(input.properties.state) != "enabled"
}

dbsec_threat_retention = false {
    lower(input.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    input.properties.retentionDays <= 90
}

dbsec_threat_retention_err = "Azure SQL DB with Threat Retention less than 91 days" {
    dbsec_threat_retention == false
}

#
# Azure SQL DB with disabled Email service and co-administrators for Threat Detection (264)
#

default dbsec_threat_email = null

dbsec_threat_email {
    lower(input.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    lower(input.properties.state) == "enabled"
    input.properties.emailAccountAdmins == true
    count(input.properties.emailAddresses) > 0
}

dbsec_threat_email = false {
    lower(input.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    lower(input.properties.state) != "enabled"
}

dbsec_threat_email = false {
    lower(input.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    input.properties.emailAccountAdmins == false
}

dbsec_threat_email = false {
    lower(input.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    count(input.properties.emailAddresses) == 0
}

dbsec_threat_email_err = "Azure SQL DB with disabled Email service and co-administrators for Threat Detection" {
    dbsec_threat_email == false
}

#
# Azure SQL Server threat detection alerts not enabled for all threat types (270)
# Threat Detection types on SQL databases is misconfigured (305)
#

default dbsec_threat_alert = null

dbsec_threat_alert {
    lower(input.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    lower(input.properties.state) == "enabled"
    count(input.properties.disabledAlerts) == 0
}

dbsec_threat_alert = false {
    lower(input.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    lower(input.properties.state) != "enabled"
}

dbsec_threat_alert = false {
    lower(input.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    count(input.properties.disabledAlerts) > 0
}

dbsec_threat_alert_err = "Azure SQL Server threat detection alerts not enabled for all threat types" {
    dbsec_threat_alert == false
}

#
# Send alerts on field value on SQL Databases is misconfigured (297)
#

default sql_alert = null

sql_alert {
    input.type == "Microsoft.Sql/servers/auditingSettings"
    lower(input.properties.state) == "enabled"
    input.properties.emailAccountAdmins == true
}

sql_alert = false {
    input.type == "Microsoft.Sql/servers/auditingSettings"
    lower(input.properties.state) != "enabled"
}

sql_alert = false {
    input.type == "Microsoft.Sql/servers/auditingSettings"
    input.properties.emailAccountAdmins == false
}

sql_alert_err = "Send alerts on field value on SQL Databases is misconfigured" {
    sql_alert == false
}

#
# Threat Detection on SQL databases is set to Off (305)
#

default dbsec_threat_off = false

dbsec_threat_off {
    lower(input.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    lower(input.properties.state) == "enabled"
}

dbsec_threat_off = false {
    lower(input.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    lower(input.properties.state) == "enabled"
}

dbsec_threat_off_err = "Threat Detection on SQL databases is set to Off" {
    dbsec_threat_off == false
}
