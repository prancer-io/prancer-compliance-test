package rule

#
# PR-AZR-0103-ARM
#

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies
# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances/securityalertpolicies

default sql_server_alert = null

azure_sql_security_alert_disabled["sql_server_security_alert_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    sql_resources.properties.state == "Disabled"
}

azure_sql_security_alert_disabled["sql_server_security_alert_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    resource.properties.state == "Disabled"
}

sql_server_alert {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    not azure_sql_security_alert_disabled["sql_server_security_alert_disabled"]
}

sql_server_alert = false {
    azure_sql_security_alert_disabled["sql_server_security_alert_disabled"]
}

sql_server_alert_err = "Security alert for SQL server is Disabled" {
    azure_sql_security_alert_disabled["sql_server_security_alert_disabled"]
}

sql_server_alert_metadata := {
    "Policy Code": "PR-AZR-0103-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "",
    "Policy Description": "",
    "Resource Type": "securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}


default sql_managed_instance_alert = null

azure_sql_security_alert_disabled["sql_instance_security_alert_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    sql_resources.properties.state == "Disabled"
}

azure_sql_security_alert_disabled["sql_instance_security_alert_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances/securityalertpolicies"
    resource.properties.state == "Disabled"
}

sql_managed_instance_alert {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    not azure_sql_security_alert_disabled["sql_instance_security_alert_disabled"]
}

sql_managed_instance_alert = false {
    azure_sql_security_alert_disabled["sql_instance_security_alert_disabled"]
}

sql_managed_instance_alert_err = "Security alert for SQL managed instance is Disabled" {
    azure_sql_security_alert_disabled["sql_instance_security_alert_disabled"]
}

sql_managed_instance_alert_metadata := {
    "Policy Code": "",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Security alert for SQL managed instance is Disabled",
    "Policy Description": "Security alert for SQL managed instance is Disabled",
    "Resource Type": "securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}
