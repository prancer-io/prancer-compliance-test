package rule

#

#

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies
# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances/securityalertpolicies

# PR-AZR-0102-ARM

default sql_logical_server_alert = null

azure_attribute_absence["sql_logical_server_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.state
}


azure_sql_security_alert_disabled["sql_logical_server_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    lower(sql_resources.properties.state) == "disabled"
}


sql_logical_server_alert {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    resource := input.resources[_]
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not azure_attribute_absence["sql_logical_server_alert"]
    not azure_sql_security_alert_disabled["sql_logical_server_alert"]
}

sql_logical_server_alert = false {
    azure_attribute_absence["sql_logical_server_alert"]
}

sql_logical_server_alert = false {
    azure_sql_security_alert_disabled["sql_logical_server_alert"]
}

sql_logical_server_alert_miss_err = "securityAlertPolicies property 'state' is missing from the resource" {
    azure_attribute_absence["sql_logical_server_alert"]
}

sql_logical_server_alert_err = "Security alert is currently not enabled on SQL Server resource." {
    azure_sql_security_alert_disabled["sql_logical_server_alert"]
}

sql_logical_server_alert_metadata := {
    "Policy Code": "PR-AZR-0102-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Security Alert is enabled on Azure SQL Logical Server",
    "Policy Description": "Advanced data security should be enabled on your SQL servers.",
    "Resource Type": "securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}


# PR-AZR-0127-ARM

default sql_server_alert = null

azure_attribute_absence["sql_server_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not resource.properties.state
}


azure_sql_security_alert_disabled["sql_server_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    lower(resource.properties.state) == "disabled"
}

sql_server_alert {
    lower(input.resources[_].type) == "microsoft.sql/servers/securityalertpolicies"
    not azure_attribute_absence["sql_server_alert"]
    not azure_sql_security_alert_disabled["sql_server_alert"]
}

sql_server_alert = false {
    azure_attribute_absence["sql_server_alert"]
}

sql_server_alert = false {
    azure_sql_security_alert_disabled["sql_server_alert"]
}

sql_server_alert_miss_err = "securityAlertPolicies property 'state' is missing from the resource" {
    azure_attribute_absence["sql_server_alert"]
}

sql_server_alert_err = "Security alert is currently not enabled on SQL Server resource." {
    azure_sql_security_alert_disabled["sql_server_alert"]
}

sql_server_alert_metadata := {
    "Policy Code": "PR-AZR-0127-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Security Alert is enabled on Azure SQL Server",
    "Policy Description": "Advanced data security should be enabled on your SQL servers.",
    "Resource Type": "securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}



# PR-AZR-0103-ARM

default sql_managed_instance_alert = null


azure_attribute_absence["sql_managed_instance_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances/securityalertpolicies"
    not resource.properties.state
}


azure_sql_security_alert_disabled["sql_managed_instance_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances/securityalertpolicies"
    lower(resource.properties.state) == "disabled"
}

sql_managed_instance_alert {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances/securityalertpolicies"
    not azure_attribute_absence["sql_managed_instance_alert"]
    not azure_sql_security_alert_disabled["sql_managed_instance_alert"]
}

sql_managed_instance_alert = false {
    azure_attribute_absence["sql_managed_instance_alert"]
}

sql_managed_instance_alert = false {
    azure_sql_security_alert_disabled["sql_managed_instance_alert"]
}

sql_managed_instance_alert_miss_err = "securityAlertPolicies property 'state' is missing from the resource" {
    azure_attribute_absence["sql_managed_instance_alert"]
}

sql_managed_instance_alert_err = "Security alert is currently not enabled on SQL managed instance resource." {
    azure_sql_security_alert_disabled["sql_managed_instance_alert"]
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
