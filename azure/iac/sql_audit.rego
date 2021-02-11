package rule

#
# PR_AZR_0003_ARM
#

default sql_audit = null

azure_security_alert_disabled["security_alert_policies_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    sql_resources.properties.state == "Disabled"
}

sql_audit {
    lower(input.resources[_].type) == "microsoft.sql/servers/administrators"
    not azure_security_alert_disabled["security_alert_policies_disabled"]
}

sql_audit = false {
    azure_security_alert_disabled["security_alert_policies_disabled"]
}

sql_audit_err = "Auditing for SQL database is Disabled" {
    azure_security_alert_disabled["security_alert_policies_disabled"]
}
