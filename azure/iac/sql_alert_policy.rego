package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies
# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances/securityalertpolicies

# PR-AZR-ARM-SQL-030
# This local server child resource is not available in Terraform yet.
default sql_logical_server_alert = null

azure_attribute_absence["sql_logical_server_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.state
}

source_path[{"sql_logical_server_alert":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.state
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","state"]]
    }
}


azure_sql_security_alert_disabled["sql_logical_server_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    lower(sql_resources.properties.state) == "disabled"
}

source_path[{"sql_logical_server_alert":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    lower(sql_resources.properties.state) == "disabled"
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","state"]]
    }
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
    "Policy Code": "PR-AZR-ARM-SQL-030",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Security Alert is enabled on Azure SQL Logical Server",
    "Policy Description": "Advanced data security should be enabled on your SQL servers.",
    "Resource Type": "securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}


# PR-AZR-ARM-SQL-031

default sql_server_alert = null

azure_attribute_absence["sql_server_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not resource.properties.state
}

source_path[{"sql_server_alert":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not resource.properties.state
    metadata:= {
        "resource_path": [["resources",i,"properties","state"]]
    }
}


azure_sql_security_alert_disabled["sql_server_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    lower(resource.properties.state) == "disabled"
}

source_path[{"sql_server_alert":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    lower(resource.properties.state) == "disabled"
    metadata:= {
        "resource_path": [["resources",i,"properties","state"]]
    }
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
    "Policy Code": "PR-AZR-ARM-SQL-031",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Security Alert is enabled on Azure SQL Server",
    "Policy Description": "Advanced data security should be enabled on your SQL servers.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}



# PR-AZR-ARM-SQL-032
# SQL Managed Instance resource still not available for Terraform yet. 
# see: https://github.com/hashicorp/terraform-provider-azurerm/issues/1747 for details

default sql_managed_instance_alert = null


azure_attribute_absence["sql_managed_instance_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances/securityalertpolicies"
    not resource.properties.state
}

source_path[{"sql_managed_instance_alert":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/managedinstances/securityalertpolicies"
    not resource.properties.state
    metadata:= {
        "resource_path": [["resources",i,"properties","state"]]
    }
}

azure_sql_security_alert_disabled["sql_managed_instance_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances/securityalertpolicies"
    lower(resource.properties.state) == "disabled"
}

source_path[{"sql_managed_instance_alert":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/managedinstances/securityalertpolicies"
    lower(resource.properties.state) == "disabled"
    metadata:= {
        "resource_path": [["resources",i,"properties","state"]]
    }
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
    "Policy Code": "PR-AZR-ARM-SQL-032",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Advanced data security should be enabled on your SQL managed instance.",
    "Policy Description": "Advanced data security should be enabled on your SQL managed instance.",
    "Resource Type": "microsoft.sql/managedinstances/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances/securityalertpolicies"
}



# PR-AZR-ARM-SQL-033
#

default sql_logical_server_email_account = null

azure_issue["sql_logical_server_email_account"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.emailAccountAdmins
}

source_path[{"sql_logical_server_email_account":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.emailAccountAdmins
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","emailAccountAdmins"]]
    }
}

azure_issue["sql_logical_server_email_account"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    sql_resources.properties.emailAccountAdmins != true
}

source_path[{"sql_logical_server_email_account":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    sql_resources.properties.emailAccountAdmins != true
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","emailAccountAdmins"]]
    }
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
    "Policy Code": "PR-AZR-ARM-SQL-033",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server",
    "Policy Description": "VA scan reports and alerts will be sent to admins and subscription owners by enabling setting 'Also send email notifications to admins and subscription owners'. This may help in reducing time required for identifying risks and taking corrective measures.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}



# PR-AZR-ARM-SQL-034
#

default sql_server_email_account = null

azure_issue["sql_server_email_account"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not resource.properties.emailAccountAdmins
}

source_path[{"sql_server_email_account":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not resource.properties.emailAccountAdmins
        "resource_path": [["resources",i,"properties","emailAccountAdmins"]]
    }
}

azure_issue["sql_server_email_account"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    resource.properties.emailAccountAdmins != true
}

source_path[{"sql_server_email_account":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    resource.properties.emailAccountAdmins != true
        "resource_path": [["resources",i,"properties","emailAccountAdmins"]]
    }
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
    "Policy Code": "PR-AZR-ARM-SQL-034",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server",
    "Policy Description": "VA scan reports and alerts will be sent to admins and subscription owners by enabling setting 'Also send email notifications to admins and subscription owners'. This may help in reducing time required for identifying risks and taking corrective measures.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}



# PR-AZR-ARM-SQL-035
#

default sql_logical_server_email_addressess = null


azure_attribute_absence["sql_logical_server_email_addressess"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.emailAddresses
}

source_path[{"sql_logical_server_email_addressess":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.emailAddresses
        "resource_path": [["resources",i,"resources",j,"properties","emailAddresses"]]
    }
}

azure_issue["sql_logical_server_email_addressess"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    count(sql_resources.properties.emailAddresses) == 0  
}

source_path[{"sql_logical_server_email_addressess":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    count(sql_resources.properties.emailAddresses) == 0  
        "resource_path": [["resources",i,"resources",j,"properties","emailAddresses"]]
    }
}

sql_logical_server_email_addressess {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    resource := input.resources[_]
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not azure_attribute_absence["sql_logical_server_email_addressess"]
    not azure_issue["sql_logical_server_email_addressess"]
}


sql_logical_server_email_addressess = false {
    azure_attribute_absence["sql_logical_server_email_addressess"]
}


sql_logical_server_email_addressess = false {
    azure_issue["sql_logical_server_email_addressess"]
}


sql_logical_server_email_addressess_err = "Azure SQL security alert policy attribute 'emailAddresses' is missing from the resource" {
    azure_attribute_absence["sql_logical_server_email_addressess"]
} else = "Azure SQL security alert policy is currently not configured to sent alert to the account administrators via email" {
    azure_issue["sql_logical_server_email_addressess"]
}


sql_logical_server_email_addressess_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-035",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure SQL Security Alert Policy should be configured to send alerts to the account administrators and configured email addresses",
    "Policy Description": "Provide the email address where alerts will be sent when anomalous activities are detected on SQL servers.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}






# PR-AZR-ARM-SQL-036
#

default sql_server_email_addressess = null


azure_attribute_absence["sql_server_email_addressess"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not resource.properties.emailAddresses
}

source_path[{"sql_server_email_addressess":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not resource.properties.emailAddresses 
        "resource_path": [["resources",i,"properties","emailAddresses"]]
    }
}

azure_issue["sql_server_email_addressess"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    count(resource.properties.emailAddresses) == 0  
}

source_path[{"sql_server_email_addressess":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    count(resource.properties.emailAddresses) == 0  
        "resource_path": [["resources",i,"properties","emailAddresses"]]
    }
}

sql_server_email_addressess {
    lower(input.resources[_].type) == "microsoft.sql/servers/securityalertpolicies"
    not azure_attribute_absence["sql_server_email_addressess"]
    not azure_issue["sql_server_email_addressess"]
}


sql_server_email_addressess = false {
    azure_attribute_absence["sql_server_email_addressess"]
}


sql_server_email_addressess = false {
    azure_issue["sql_server_email_addressess"]
}


sql_server_email_addressess_err = "Azure SQL security alert policy attribute 'emailAddresses' is missing from the resource" {
    azure_attribute_absence["sql_server_email_addressess"]
} else = "Azure SQL security alert policy is currently not configured to sent alert to the account administrators via email" {
    azure_issue["sql_server_email_addressess"]
}


sql_server_email_addressess_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-036",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure SQL Security Alert Policy should be configured to send alert to the account administrators and configured email addresses",
    "Policy Description": "Provide the email address where alerts will be sent when anomalous activities are detected on SQL servers.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}





# PR-AZR-ARM-SQL-037
#

default sql_logical_server_retention_days = null


azure_attribute_absence["sql_logical_server_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.retentionDays
}

source_path[{"sql_logical_server_retention_days":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.retentionDays
        "resource_path": [["resources",i,"resources",j,"properties","retentionDays"]]
    }
}

azure_issue["sql_logical_server_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    to_number(sql_resources.properties.retentionDays) == 0  
}

source_path[{"sql_logical_server_retention_days":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    to_number(sql_resources.properties.retentionDays) == 0
        "resource_path": [["resources",i,"resources",j,"properties","retentionDays"]]
    }
}


azure_issue["sql_logical_server_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    to_number(sql_resources.properties.retentionDays) >= 90 
}

source_path[{"sql_logical_server_retention_days":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    to_number(sql_resources.properties.retentionDays) >= 90 
        "resource_path": [["resources",i,"resources",j,"properties","retentionDays"]]
    }
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
    "Policy Code": "PR-AZR-ARM-SQL-037",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure SQL Server Threat Detection is Enabled and Retention Logs are greater than 90 days",
    "Policy Description": "Azure SQL Database Threat Detection is a security intelligence feature built into the Azure SQL Database service. Working around the clock to learn, profile and detect anomalous database activities, Azure SQL Database Threat Detection identifies potential threats to the database. Security officers or other designated administrators can get an immediate notification about suspicious database activities as they occur. Each notification provides details of the suspicious activity and recommends how to further investigate and mitigate the threat.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}






# PR-AZR-ARM-SQL-038
#

default sql_server_retention_days = null


azure_attribute_absence["sql_server_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not resource.properties.retentionDays
}

source_path[{"sql_server_retention_days":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not resource.properties.retentionDays
        "resource_path": [["resources",i,"properties","retentionDays"]]
    }
}

azure_issue["sql_server_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    to_number(resource.properties.retentionDays) == 0  
}

source_path[{"sql_server_retention_days":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    to_number(resource.properties.retentionDays) == 0  
        "resource_path": [["resources",i,"properties","retentionDays"]]
    }
}


azure_issue["sql_server_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    to_number(resource.properties.retentionDays) >= 90 
}

source_path[{"sql_server_retention_days":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    to_number(resource.properties.retentionDays) >= 90
        "resource_path": [["resources",i,"properties","retentionDays"]]
    }
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
    "Policy Code": "PR-AZR-ARM-SQL-038",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure SQL Server Threat Detection is Enabled and Retention Logs are greater than 90 days",
    "Policy Description": "Azure SQL Database Threat Detection is a security intelligence feature built into the Azure SQL Database service. Working around the clock to learn, profile and detect anomalous database activities, Azure SQL Database Threat Detection identifies potential threats to the database. Security officers or other designated administrators can get an immediate notification about suspicious database activities as they occur. Each notification provides details of the suspicious activity and recommends how to further investigate and mitigate the threat.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}



# PR-AZR-ARM-SQL-039
#

default sql_logical_server_disabled_alerts = null

azure_attribute_absence["sql_logical_server_disabled_alerts"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.disabledAlerts
}

source_path[{"sql_logical_server_disabled_alerts":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.disabledAlerts
        "resource_path": [["resources",i,"resources",j,"properties","disabledAlerts"]]
    }
}

azure_issue["sql_logical_server_disabled_alerts"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    count(sql_resources.properties.disabledAlerts) > 0
}

source_path[{"sql_logical_server_disabled_alerts":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    count(sql_resources.properties.disabledAlerts) > 0
        "resource_path": [["resources",i,"resources",j,"properties","disabledAlerts"]]
    }
}

sql_logical_server_disabled_alerts {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not azure_attribute_absence["sql_logical_server_disabled_alerts"]
    not azure_issue["sql_logical_server_disabled_alerts"]
}


sql_logical_server_disabled_alerts {
    azure_attribute_absence["sql_logical_server_disabled_alerts"]
}

sql_logical_server_disabled_alerts = false {
    azure_issue["sql_logical_server_disabled_alerts"]
}

sql_logical_server_disabled_alerts_err = "Azure SQL Server Security Alert Policy currently have one or more alert type in disabled alerts list" {
    azure_issue["sql_logical_server_disabled_alerts"]
}


sql_logical_server_disabled_alerts_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-039",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure SQL Server threat detection alerts should be enabled for all threat types",
    "Policy Description": "Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification.<br><br>This policy identifies Azure SQL servers that have disabled the detection of one or more threat types. To protect your SQL Servers, as a best practice, enable ADS detection for all types of threats.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/securityalertpolicies"
}





# PR-AZR-ARM-SQL-040
#

default sql_server_disabled_alerts = null

azure_attribute_absence["sql_server_disabled_alerts"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not resource.properties.disabledAlerts
}

source_path[{"sql_server_disabled_alerts":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not resource.properties.disabledAlerts
        "resource_path": [["resources",i,"properties","disabledAlerts"]]
    }
}

azure_issue["sql_server_disabled_alerts"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    count(resource.properties.disabledAlerts) > 0
}

source_path[{"sql_server_disabled_alerts":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    count(resource.properties.disabledAlerts) > 0
        "resource_path": [["resources",i,"properties","disabledAlerts"]]
    }
}

sql_server_disabled_alerts {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not azure_attribute_absence["sql_server_disabled_alerts"]
    not azure_issue["sql_server_disabled_alerts"]
}


sql_server_disabled_alerts {
    azure_attribute_absence["sql_server_disabled_alerts"]
}

sql_server_disabled_alerts = false {
    azure_issue["sql_server_disabled_alerts"]
}

sql_server_disabled_alerts_err = "Azure SQL Server Security Alert Policy currently have one or more alert type in disabled alerts list" {
    azure_issue["sql_server_disabled_alerts"]
}


sql_server_disabled_alerts_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-040",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure SQL Server threat detection alerts should be enabled for all threat types",
    "Policy Description": "Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification.<br><br>This policy identifies Azure SQL servers that have disabled the detection of one or more threat types. To protect your SQL Servers, as a best practice, enable ADS detection for all types of threats.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/securityalertpolicies"
}