package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies
# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances/securityalertpolicies

# PR-AZR-0102-ARM
# This local server child resource is not available in Terraform yet.
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

sql_logical_server_alert_err = "Security alert is currently not enabled on SQL Logical Server" {
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


# PR-AZR-0129-ARM

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

sql_server_alert_err = "Security alert is currently not enabled on SQL Server" {
    azure_sql_security_alert_disabled["sql_server_alert"]
}

sql_server_alert_metadata := {
    "Policy Code": "PR-AZR-0129-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Security Alert is enabled on Azure SQL Server",
    "Policy Description": "Advanced data security should be enabled on your SQL servers.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}



# PR-AZR-0103-ARM
# SQL Managed Instance resource still not available for Terraform yet. 
# see: https://github.com/hashicorp/terraform-provider-azurerm/issues/1747 for details

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
    "Resource Type": "microsoft.sql/managedinstances/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances/securityalertpolicies"
}



# PR-AZR-0147-ARM

default sql_logical_server_email_account_admins = null

azure_attribute_absence["sql_logical_server_email_account_admins"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.emailAccountAdmins
}


azure_issue["sql_logical_server_email_account_admins"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    sql_resources.properties.emailAccountAdmins != true 
}


sql_logical_server_email_account_admins {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    resource := input.resources[_]
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not azure_attribute_absence["sql_logical_server_email_account_admins"]
    not azure_issue["sql_logical_server_email_account_admins"]
}

sql_logical_server_email_account_admins = false {
    azure_attribute_absence["sql_logical_server_email_account_admins"]
}

sql_logical_server_email_account_admins = false {
    azure_issue["sql_logical_server_email_account_admins"]
}


sql_logical_server_email_account_admins_err = "microsoft.sql/servers/securityalertpolicies resource property 'emailAccountAdmins' missing in the resource" {
    azure_attribute_absence["sql_logical_server_email_account_admins"]
} else = "SQL servers do not have email service and co-administrators enabled" {
    azure_issue["sql_logical_server_email_account_admins"]
}

sql_logical_server_email_account_admins_metadata := {
    "Policy Code": "PR-AZR-0147-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "SQL servers should have email service and co-administrators enabled",
    "Policy Description": "Enable Service and Co-administrators to receive security alerts from the SQL server. We recommended providing the email address to receive alerts ensures that any detection of anomalous activities reported",
    "Resource Type": "securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}




# PR-AZR-0148-ARM

default sql_server_email_account_admins = null

azure_attribute_absence["sql_server_email_account_admins"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not resource.properties.emailAccountAdmins
}


azure_issue["sql_server_email_account_admins"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    resource.properties.emailAccountAdmins != true
}

sql_server_email_account_admins {
    lower(input.resources[_].type) == "microsoft.sql/servers/securityalertpolicies"
    not azure_attribute_absence["sql_server_email_account_admins"]
    not azure_sql_security_alert_disabled["sql_server_email_account_admins"]
}

sql_server_email_account_admins = false {
    azure_attribute_absence["sql_server_email_account_admins"]
}

sql_server_email_account_admins = false {
    azure_sql_security_alert_disabled["sql_server_email_account_admins"]
}

sql_server_email_account_admins_err = "microsoft.sql/servers/securityalertpolicies resource property 'emailAccountAdmins' missing in the resource" {
    azure_attribute_absence["sql_server_email_account_admins"]
} else = "SQL servers do not have email service and co-administrators enabled" {
    azure_issue["sql_server_email_account_admins"]
}

sql_server_email_account_admins_metadata := {
    "Policy Code": "PR-AZR-0148-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "SQL servers should have email service and co-administrators enabled",
    "Policy Description": "Enable Service and Co-administrators to receive security alerts from the SQL server. We recommended providing the email address to receive alerts ensures that any detection of anomalous activities reported",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}
