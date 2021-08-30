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



# PR-AZR-0192-ARM
#

default sql_logical_server_email_account = null

azure_issue["sql_logical_server_email_account"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.emailAccountAdmins
}

azure_issue["sql_logical_server_email_account"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    sql_resources.properties.emailAccountAdmins != true
}


sql_logical_server_email_account {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not azure_attribute_absence["sql_logical_server_email_account"]
    not azure_issue["sql_logical_server_email_account"]
}


sql_logical_server_email_account = false {
    azure_attribute_absence["sql_logical_server_email_account"]
}


sql_logical_server_email_account = false {
    azure_issue["sql_logical_server_email_account"]
}

sql_logical_server_email_account_err = "microsoft.sql/servers/securityalertpolicies property 'emailAccountAdmins' need to be exist. Its missing from the resource." {
    azure_attribute_absence["sql_logical_server_email_account"]
} else = "Threat Detection alert currently is not configured to sent notification to the sql server account administrators" {
    azure_issue["sql_logical_server_email_account"]
}

sql_logical_server_email_account_metadata := {
    "Policy Code": "PR-AZR-0192-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server",
    "Policy Description": "VA scan reports and alerts will be sent to admins and subscription owners by enabling setting 'Also send email notifications to admins and subscription owners'. This may help in reducing time required for identifying risks and taking corrective measures.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}



# PR-AZR-0193-ARM
#

default sql_server_email_account = null

azure_issue["sql_server_email_account"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not sql_resources.properties.emailAccountAdmins
}

azure_issue["sql_server_email_account"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    sql_resources.properties.emailAccountAdmins != true
}


sql_server_email_account {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not azure_attribute_absence["sql_server_email_account"]
    not azure_issue["sql_server_email_account"]
}


sql_server_email_account = false {
    azure_attribute_absence["sql_server_email_account"]
}


sql_server_email_account = false {
    azure_issue["sql_server_email_account"]
}

sql_server_email_account_err = "microsoft.sql/servers/securityalertpolicies property 'emailAccountAdmins' need to be exist. Its missing from the resource." {
    azure_attribute_absence["sql_server_email_account"]
} else = "Threat Detection alert currently is not configured to sent notification to the sql server account administrators" {
    azure_issue["sql_server_email_account"]
}

sql_server_email_account_metadata := {
    "Policy Code": "PR-AZR-0193-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server",
    "Policy Description": "VA scan reports and alerts will be sent to admins and subscription owners by enabling setting 'Also send email notifications to admins and subscription owners'. This may help in reducing time required for identifying risks and taking corrective measures.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}



# PR-AZR-0194-ARM
#

default sql_logical_server_retention_days = null


azure_attribute_absence["sql_logical_server_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.emailAddresses
}

azure_issue["sql_logical_server_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    count(sql_resources.properties.emailAddresses) == 0  
}

sql_logical_server_retention_days {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    resource := input.resources[_]
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not azure_attribute_absence["sql_logical_server_retention_days"]
    not azure_issue["sql_logical_server_retention_days"]
}


sql_logical_server_retention_days = false {
    azure_attribute_absence["sql_logical_server_retention_days"]
}


sql_logical_server_retention_days = false {
    azure_issue["sql_logical_server_retention_days"]
}


sql_logical_server_retention_days_err = "Azure SQL security alert policy attribute 'emailAccountAdmins' or 'emailAddresses' is missing from the resource" {
    azure_attribute_absence["sql_logical_server_retention_days"]
} else = "Azure SQL security alert policy is currently not configured to sent alert to the account administrators via email" {
    azure_issue["sql_logical_server_retention_days"]
}


sql_logical_server_retention_days_metadata := {
    "Policy Code": "PR-AZR-0194-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure SQL Security Alert Policy should be configured to send alert to the account administrators and configured email addresses",
    "Policy Description": "",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}






# PR-AZR-0195-ARM
#

default sql_server_email_addressess = null


azure_attribute_absence["sql_server_email_addressess"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.emailAddresses
}

azure_issue["sql_server_email_addressess"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    count(sql_resources.properties.emailAddresses) == 0  
}

sql_server_email_addressess {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    resource := input.resources[_]
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not azure_attribute_absence["sql_server_email_addressess"]
    not azure_issue["sql_server_email_addressess"]
}


sql_server_email_addressess = false {
    azure_attribute_absence["sql_server_email_addressess"]
}


sql_server_email_addressess = false {
    azure_issue["sql_server_email_addressess"]
}


sql_server_email_addressess_err = "Azure SQL security alert policy attribute 'emailAccountAdmins' or 'emailAddresses' is missing from the resource" {
    azure_attribute_absence["sql_server_email_addressess"]
} else = "Azure SQL security alert policy is currently not configured to sent alert to the account administrators via email" {
    azure_issue["sql_server_email_addressess"]
}


sql_server_email_addressess_metadata := {
    "Policy Code": "PR-AZR-0195-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure SQL Security Alert Policy should be configured to send alert to the account administrators and configured email addresses",
    "Policy Description": "Provide the email address where alerts will be sent when anomalous activities are detected on SQL servers.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}





# PR-AZR-0196-ARM
#

default sql_logical_server_retention_days = null


azure_attribute_absence["sql_logical_server_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.retentionDays
}

azure_issue["sql_logical_server_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    to_number(sql_resources.properties.retentionDays) == 0  
}


azure_issue["sql_logical_server_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    to_number(sql_resources.properties.retentionDays) >= 90 
}


sql_logical_server_retention_days {
    not azure_attribute_absence["sql_logical_server_retention_days"]
    azure_issue["sql_logical_server_retention_days"]
}


sql_logical_server_retention_days = false {
    azure_attribute_absence["sql_logical_server_retention_days"]
}


sql_logical_server_retention_days = false {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    resource := input.resources[_]
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not azure_issue["sql_logical_server_retention_days"]
}


sql_logical_server_retention_days_err = "Azure SQL security alert policy attribute 'retentionDays' is missing from the resource" {
    azure_attribute_absence["sql_logical_server_retention_days"]
} else = "SQL Server security alert policy Retention Days are not greater than 90 days" {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    resource := input.resources[_]
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not azure_issue["sql_logical_server_retention_days"]
}


sql_logical_server_retention_days_metadata := {
    "Policy Code": "PR-AZR-0196-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure SQL Server Threat Detection is Enabled and Retention Logs are greater than 90 days",
    "Policy Description": "Azure SQL Database Threat Detection is a security intelligence feature built into the Azure SQL Database service. Working around the clock to learn, profile and detect anomalous database activities, Azure SQL Database Threat Detection identifies potential threats to the database. Security officers or other designated administrators can get an immediate notification about suspicious database activities as they occur. Each notification provides details of the suspicious activity and recommends how to further investigate and mitigate the threat.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}






# PR-AZR-0197-ARM
#

default sql_server_retention_days = null


azure_attribute_absence["sql_server_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not sql_resources.properties.retentionDays
}

azure_issue["sql_server_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    to_number(sql_resources.properties.retentionDays) == 0  
}


azure_issue["sql_server_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    to_number(sql_resources.properties.retentionDays) >= 90 
}


sql_server_retention_days {
    not azure_attribute_absence["sql_server_retention_days"]
    azure_issue["sql_server_retention_days"]
}


sql_server_retention_days = false {
    azure_attribute_absence["sql_server_retention_days"]
}


sql_server_retention_days = false {
    lower(input.resources[_].type) == "microsoft.sql/servers/securityalertpolicies"
    not azure_issue["sql_server_retention_days"]
}


sql_server_retention_days_err = "Azure SQL security alert policy attribute 'retentionDays' is missing from the resource" {
    azure_attribute_absence["sql_server_retention_days"]
} else = "SQL Server security alert policy Retention Days are not greater than 90 days" {
    lower(input.resources[_].type) == "microsoft.sql/servers/securityalertpolicies"
    not azure_issue["sql_server_retention_days"]
}


sql_server_retention_days_metadata := {
    "Policy Code": "PR-AZR-0197-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure SQL Server Threat Detection is Enabled and Retention Logs are greater than 90 days",
    "Policy Description": "Azure SQL Database Threat Detection is a security intelligence feature built into the Azure SQL Database service. Working around the clock to learn, profile and detect anomalous database activities, Azure SQL Database Threat Detection identifies potential threats to the database. Security officers or other designated administrators can get an immediate notification about suspicious database activities as they occur. Each notification provides details of the suspicious activity and recommends how to further investigate and mitigate the threat.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}