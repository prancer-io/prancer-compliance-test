#
# PR-AZR-0103
#

package rule
default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/auditingsettings

default rulepass = null

sql_instance_issue["sql_instance_disabled_security_alert_policy"]{
    input.type == "Microsoft.Sql/servers/auditingSettings"
    input.properties.state != "Enabled"
}

rulepass = true {
    not sql_database_issue["sql_instance_disabled_security_alert_policy"]
}

rulepass = false {
    sql_database_issue["sql_instance_disabled_security_alert_policy"]
}

rulepass_err = "Azure SQL Instance has not enabled security alert policy" {
    sql_database_issue["sql_instance_disabled_security_alert_policy"]
}
