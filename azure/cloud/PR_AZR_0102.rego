#
# PR-AZR-0102
#

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies
# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances/securityalertpolicies

package rule
default sql_server_rulepass = null

sql_server_issue["sql_server_disabled_security_alert_policy"] {
    lower(input.type) == "microsoft.sql/servers/securityalertpolicies"
    input.properties.state != "Enabled"
}

sql_server_rulepass = true {
    not sql_database_issue["sql_server_disabled_security_alert_policy"]
}

sql_server_rulepass = false {
    sql_database_issue["sql_server_disabled_security_alert_policy"]
}

sql_server_rulepass_err = "Azure SQL Database Server has not enabled security alert policy" {
    sql_database_issue["sql_server_disabled_security_alert_policy"]
}

default sql_instance_rulepass = null

sql_instance_issue["sql_instance_disabled_security_alert_policy"]{
    lower(input.type) == "microsoft.sql/managedinstances/securityalertpolicies"
    input.properties.state != "Enabled"
}

sql_instance_rulepass = true {
    not sql_database_issue["sql_instance_disabled_security_alert_policy"]
}

sql_instance_rulepass = false {
    sql_database_issue["sql_instance_disabled_security_alert_policy"]
}

sql_instance_rulepass_err = "Azure SQL Instance has not enabled security alert policy" {
    sql_database_issue["sql_instance_disabled_security_alert_policy"]
}

metadata := {
    "Policy Code": "PR-AZR-0102",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure SQL Instance has not enabled security alert policy",
    "Policy Description": "Azure SQL Instance has not enabled security alert policy",
    "Compliance": [],
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}
