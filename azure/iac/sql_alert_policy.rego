package rule

#

#

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies
# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances/securityalertpolicies

# PR-AZR-0102-ARM

default sql_server_alert = null

azure_attribute_absence["sql_server_security_alert_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.state
}

azure_attribute_absence["sql_server_security_alert_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not resource.properties.state
}


azure_sql_security_alert_disabled["sql_server_security_alert_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    lower(sql_resources.properties.state) == "disabled"
}

azure_sql_security_alert_disabled["sql_server_security_alert_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    lower(resource.properties.state) == "disabled"
}

sql_server_alert {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    not azure_attribute_absence["sql_server_security_alert_disabled"]
    not azure_sql_security_alert_disabled["sql_server_security_alert_disabled"]
}

sql_server_alert = false {
    azure_attribute_absence["sql_server_security_alert_disabled"]
}

sql_server_alert = false {
    azure_sql_security_alert_disabled["sql_server_security_alert_disabled"]
}

sql_server_alert_err = "Security alert for SQL server missing in the resource!" {
    azure_attribute_absence["sql_server_security_alert_disabled"]
}

sql_server_alert_err = "Security alert for SQL server is Disabled" {
    azure_sql_security_alert_disabled["sql_server_security_alert_disabled"]
}

sql_server_alert_metadata := {
    "Policy Code": "PR-AZR-0102-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Advanced data security should be enabled on your SQL servers.",
    "Policy Description": "Advanced data security should be enabled on your SQL servers.",
    "Resource Type": "securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}

# PR-AZR-0103-ARM

default sql_managed_instance_alert = null

azure_attribute_absence["sql_instance_security_alert_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.state
}

azure_attribute_absence["sql_instance_security_alert_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances/securityalertpolicies"
    not resource.properties.state
}

azure_sql_security_alert_disabled["sql_instance_security_alert_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    lower(sql_resources.properties.state) == "disabled"
}

azure_sql_security_alert_disabled["sql_instance_security_alert_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances/securityalertpolicies"
    lower(resource.properties.state) == "disabled"
}

sql_managed_instance_alert {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    not azure_attribute_absence["sql_instance_security_alert_disabled"]
    not azure_sql_security_alert_disabled["sql_instance_security_alert_disabled"]
}

sql_managed_instance_alert = false {
    azure_attribute_absence["sql_instance_security_alert_disabled"]
}

sql_managed_instance_alert = false {
    azure_sql_security_alert_disabled["sql_instance_security_alert_disabled"]
}

sql_managed_instance_alert_err = "Security alert for SQL server missing in the resource!" {
    azure_attribute_absence["sql_instance_security_alert_disabled"]
}

sql_managed_instance_alert_err = "Security alert for SQL managed instance is Disabled" {
    azure_sql_security_alert_disabled["sql_instance_security_alert_disabled"]
}

sql_managed_instance_alert_metadata := {
    "Policy Code": "PR-AZR-0103-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Advanced data security should be enabled on your SQL managed instance.",
    "Policy Description": "Advanced data security should be enabled on your SQL managed instance.",
    "Resource Type": "securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances/securityalertpolicies"
}
