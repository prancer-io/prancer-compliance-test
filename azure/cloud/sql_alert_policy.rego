package rule

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies
# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances/securityalertpolicies

# PR-AZR-CLD-SQL-030
# This local server child resource is not available in Terraform yet.
# Not valid for cloud provider as cloud seperates all the child resources into seperate resource

# default sql_logical_server_alert = null

# azure_attribute_absence["sql_logical_server_alert"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers"
#     sql_resources := resource.resources[_]
#     lower(sql_resources.type) == "securityalertpolicies"
#     not sql_resources.properties.state
# }

# azure_sql_security_alert_disabled["sql_logical_server_alert"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers"
#     sql_resources := resource.resources[_]
#     lower(sql_resources.type) == "securityalertpolicies"
#     lower(sql_resources.properties.state) == "disabled"
# }

# sql_logical_server_alert {
#     lower(input.resources[_].type) == "microsoft.sql/servers"
#     resource := input.resources[_]
#     sql_resources := resource.resources[_]
#     lower(sql_resources.type) == "securityalertpolicies"
#     not azure_attribute_absence["sql_logical_server_alert"]
#     not azure_sql_security_alert_disabled["sql_logical_server_alert"]
# }

# sql_logical_server_alert = false {
#     azure_attribute_absence["sql_logical_server_alert"]
# }

# sql_logical_server_alert = false {
#     azure_sql_security_alert_disabled["sql_logical_server_alert"]
# }

# sql_logical_server_alert_miss_err = "securityAlertPolicies property 'state' is missing from the resource" {
#     azure_attribute_absence["sql_logical_server_alert"]
# }

# sql_logical_server_alert_err = "Security alert is currently not enabled on SQL Logical Server" {
#     azure_sql_security_alert_disabled["sql_logical_server_alert"]
# }

# sql_logical_server_alert_metadata := {
#     "Policy Code": "PR-AZR-CLD-SQL-030",
#     "Type": "Cloud",
#     "Product": "AZR",
#     "Language": "",
#     "Policy Title": "Ensure Security Alert is enabled on Azure SQL Logical Server",
#     "Policy Description": "Advanced data security should be enabled on your SQL servers.",
#     "Resource Type": "securityalertpolicies",
#     "Policy Help URL": "",
#     "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
# }


# PR-AZR-CLD-SQL-031

default sql_server_alert = null

azure_attribute_absence["sql_server_alert"] {
    count([c | lower(input.resources[_].type) == "microsoft.sql/servers/securityalertpolicies"; c := 1]) == 0
}

# azure_attribute_absence["sql_server_alert"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
#     not resource.dependsOn
# }

azure_attribute_absence["sql_server_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not resource.properties.state
}

azure_issue["sql_server_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.sql/servers/securityalertpolicies";
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.properties.state) == "enabled";
              c := 1]) == 0
}

sql_server_alert {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    not azure_attribute_absence["sql_server_alert"]
    not azure_issue["sql_server_alert"]
}

sql_server_alert = false {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_attribute_absence["sql_server_alert"]
}

sql_server_alert = false {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_issue["sql_server_alert"]
}

sql_server_alert_err = "Security alert is currently not enabled on SQL Server" {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_issue["sql_server_alert"]
} else = "securityAlertPolicies property 'state' is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_attribute_absence["sql_server_alert"]
}

sql_server_alert_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-031",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Security Alert is enabled on Azure SQL Server",
    "Policy Description": "Advanced data security should be enabled on your SQL servers.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}



# PR-AZR-CLD-SQL-032
# SQL Managed Instance resource still not available for Terraform yet. 
# see: https://github.com/hashicorp/terraform-provider-azurerm/issues/1747 for details

default sql_managed_instance_alert = null

azure_attribute_absence["sql_managed_instance_alert"] {
    count([c | lower(input.resources[_].type) == "microsoft.sql/managedinstances/securityalertpolicies"; c := 1]) == 0
}

# azure_attribute_absence["sql_managed_instance_alert"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/managedinstances/securityalertpolicies"
#     not resource.dependsOn
# }

azure_attribute_absence["sql_managed_instance_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances/securityalertpolicies"
    not resource.properties.state
}

azure_issue["sql_managed_instance_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.sql/managedinstances/securityalertpolicies";
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.properties.state) == "enabled";
              c := 1]) == 0
}

sql_managed_instance_alert {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    not azure_attribute_absence["sql_managed_instance_alert"]
    not azure_issue["sql_managed_instance_alert"]
}

sql_managed_instance_alert = false {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    azure_attribute_absence["sql_managed_instance_alert"]
}

sql_managed_instance_alert = false {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    azure_issue["sql_managed_instance_alert"]
}

sql_managed_instance_alert_err = "Security alert is currently not enabled on SQL managed instance resource." {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    azure_issue["sql_managed_instance_alert"]
} else = "securityAlertPolicies property 'state' is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    azure_attribute_absence["sql_managed_instance_alert"]
}

sql_managed_instance_alert_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-032",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Advanced data security should be enabled on your SQL managed instance.",
    "Policy Description": "Advanced data security should be enabled on your SQL managed instance.",
    "Resource Type": "microsoft.sql/managedinstances/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances/securityalertpolicies"
}


# PR-AZR-CLD-SQL-033
# Not valid for cloud provider as cloud seperates all the child resources into seperate resource

# default sql_logical_server_email_account = null

# azure_issue["sql_logical_server_email_account"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers"
#     sql_resources := resource.resources[_]
#     lower(sql_resources.type) == "securityalertpolicies"
#     not sql_resources.properties.emailAccountAdmins
# }


# azure_issue["sql_logical_server_email_account"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers"
#     sql_resources := resource.resources[_]
#     lower(sql_resources.type) == "securityalertpolicies"
#     sql_resources.properties.emailAccountAdmins != true
# }


# sql_logical_server_email_account {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers"
#     sql_resources := resource.resources[_]
#     lower(sql_resources.type) == "securityalertpolicies"
#     not azure_attribute_absence["sql_logical_server_email_account"]
#     not azure_issue["sql_logical_server_email_account"]
# }


# sql_logical_server_email_account = false {
#     azure_attribute_absence["sql_logical_server_email_account"]
# }


# sql_logical_server_email_account = false {
#     azure_issue["sql_logical_server_email_account"]
# }

# sql_logical_server_email_account_err = "microsoft.sql/servers/securityalertpolicies property 'emailAccountAdmins' need to be exist. Its missing from the resource." {
#     azure_attribute_absence["sql_logical_server_email_account"]
# } else = "Threat Detection alert currently is not configured to sent notification to the sql server account administrators" {
#     azure_issue["sql_logical_server_email_account"]
# }

# sql_logical_server_email_account_metadata := {
#     "Policy Code": "PR-AZR-CLD-SQL-033",
#     "Type": "Cloud",
#     "Product": "AZR",
#     "Language": "",
#     "Policy Title": "Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server",
#     "Policy Description": "VA scan reports and alerts will be sent to admins and subscription owners by enabling setting 'Also send email notifications to admins and subscription owners'. This may help in reducing time required for identifying risks and taking corrective measures.",
#     "Resource Type": "microsoft.sql/servers/securityalertpolicies",
#     "Policy Help URL": "",
#     "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
# }



# PR-AZR-CLD-SQL-034
#

default sql_server_email_account = null

azure_attribute_absence["sql_server_email_account"] {
    count([c | lower(input.resources[_].type) == "microsoft.sql/servers/securityalertpolicies"; c := 1]) == 0
}

# azure_attribute_absence["sql_server_email_account"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
#     not resource.dependsOn
# }

azure_attribute_absence["sql_server_email_account"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not resource.properties.emailAccountAdmins
}

azure_issue["sql_server_email_account"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.sql/servers/securityalertpolicies";
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              r.properties.emailAccountAdmins == true;
              c := 1]) == 0
}

sql_server_email_account {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    not azure_attribute_absence["sql_server_email_account"]
    not azure_issue["sql_server_email_account"]
}

sql_server_email_account = false {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_attribute_absence["sql_server_email_account"]
}

sql_server_email_account = false {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_issue["sql_server_email_account"]
}
 
sql_server_email_account_err = "Threat Detection alert currently is not configured to sent notification to the sql server account administrators" {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_issue["sql_server_email_account"]
} else = "microsoft.sql/servers/securityalertpolicies property 'emailAccountAdmins' need to be exist. Its missing from the resource." {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_attribute_absence["sql_server_email_account"]
}

sql_server_email_account_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-034",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server",
    "Policy Description": "VA scan reports and alerts will be sent to admins and subscription owners by enabling setting 'Also send email notifications to admins and subscription owners'. This may help in reducing time required for identifying risks and taking corrective measures.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}



# PR-AZR-CLD-SQL-035
# Not valid for cloud provider as cloud seperates all the child resources into seperate resource

# default sql_logical_server_email_addressess = null


# azure_attribute_absence["sql_logical_server_email_addressess"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers"
#     sql_resources := resource.resources[_]
#     lower(sql_resources.type) == "securityalertpolicies"
#     not sql_resources.properties.emailAddresses
# }


# azure_issue["sql_logical_server_email_addressess"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers"
#     sql_resources := resource.resources[_]
#     lower(sql_resources.type) == "securityalertpolicies"
#     count(sql_resources.properties.emailAddresses) == 0  
# }


# sql_logical_server_email_addressess {
#     lower(input.resources[_].type) == "microsoft.sql/servers"
#     resource := input.resources[_]
#     sql_resources := resource.resources[_]
#     lower(sql_resources.type) == "securityalertpolicies"
#     not azure_attribute_absence["sql_logical_server_email_addressess"]
#     not azure_issue["sql_logical_server_email_addressess"]
# }


# sql_logical_server_email_addressess = false {
#     azure_attribute_absence["sql_logical_server_email_addressess"]
# }


# sql_logical_server_email_addressess = false {
#     azure_issue["sql_logical_server_email_addressess"]
# }


# sql_logical_server_email_addressess_err = "Azure SQL security alert policy attribute 'emailAddresses' is missing from the resource" {
#     azure_attribute_absence["sql_logical_server_email_addressess"]
# } else = "Azure SQL security alert policy is currently not configured to sent alert to the account administrators via email" {
#     azure_issue["sql_logical_server_email_addressess"]
# }


# sql_logical_server_email_addressess_metadata := {
#     "Policy Code": "PR-AZR-CLD-SQL-035",
#     "Type": "Cloud",
#     "Product": "AZR",
#     "Language": "",
#     "Policy Title": "Azure SQL Security Alert Policy should be configured to send alerts to the account administrators and configured email addresses",
#     "Policy Description": "Provide the email address where alerts will be sent when anomalous activities are detected on SQL servers.",
#     "Resource Type": "microsoft.sql/servers/securityalertpolicies",
#     "Policy Help URL": "",
#     "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
# }



# PR-AZR-CLD-SQL-036
#

default sql_server_email_addressess = null

azure_attribute_absence["sql_server_email_addressess"] {
    count([c | lower(input.resources[_].type) == "microsoft.sql/servers/securityalertpolicies"; c := 1]) == 0
}

# azure_attribute_absence["sql_server_email_addressess"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
#     not resource.dependsOn
# }

azure_attribute_absence["sql_server_email_addressess"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not resource.properties.emailAddresses
}

azure_issue["sql_server_email_addressess"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.sql/servers/securityalertpolicies";
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              count(r.properties.emailAddresses) > 0;
              c := 1]) == 0
}

sql_server_email_addressess {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    not azure_attribute_absence["sql_server_email_addressess"]
    not azure_issue["sql_server_email_addressess"]
}

sql_server_email_addressess = false {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_attribute_absence["sql_server_email_addressess"]
}

sql_server_email_addressess = false {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_issue["sql_server_email_addressess"]
}
 
sql_server_email_addressess_err = "Azure SQL security alert policy is currently not configured to sent alert to the account administrators via email" {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_issue["sql_server_email_addressess"]
} else = "Azure SQL security alert policy attribute 'emailAddresses' is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_attribute_absence["sql_server_email_addressess"]
}

sql_server_email_addressess_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-036",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure SQL Security Alert Policy should be configured to send alerts to the account administrators and configured email addresses",
    "Policy Description": "Provide the email address where alerts will be sent when anomalous activities are detected on SQL servers.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}



# PR-AZR-CLD-SQL-037
# Not valid for cloud provider as cloud seperates all the child resources into seperate resource

# default sql_logical_server_retention_days = null


# azure_attribute_absence["sql_logical_server_retention_days"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers"
#     sql_resources := resource.resources[_]
#     lower(sql_resources.type) == "securityalertpolicies"
#     not sql_resources.properties.retentionDays
# }

# azure_issue["sql_logical_server_retention_days"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers"
#     sql_resources := resource.resources[_]
#     lower(sql_resources.type) == "securityalertpolicies"
#     to_number(sql_resources.properties.retentionDays) == 0  
# }


# azure_issue["sql_logical_server_retention_days"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers"
#     sql_resources := resource.resources[_]
#     lower(sql_resources.type) == "securityalertpolicies"
#     to_number(sql_resources.properties.retentionDays) >= 90 
# }


# sql_logical_server_retention_days {
#     not azure_attribute_absence["sql_logical_server_retention_days"]
#     azure_issue["sql_logical_server_retention_days"]
# }


# sql_logical_server_retention_days = false {
#     azure_attribute_absence["sql_logical_server_retention_days"]
# }


# sql_logical_server_retention_days = false {
#     lower(input.resources[_].type) == "microsoft.sql/servers"
#     resource := input.resources[_]
#     sql_resources := resource.resources[_]
#     lower(sql_resources.type) == "securityalertpolicies"
#     not azure_issue["sql_logical_server_retention_days"]
# }


# sql_logical_server_retention_days_err = "Azure SQL security alert policy attribute 'retentionDays' is missing from the resource" {
#     azure_attribute_absence["sql_logical_server_retention_days"]
# } else = "SQL Server security alert policy Retention Days are not greater than 90 days" {
#     lower(input.resources[_].type) == "microsoft.sql/servers"
#     resource := input.resources[_]
#     sql_resources := resource.resources[_]
#     lower(sql_resources.type) == "securityalertpolicies"
#     not azure_issue["sql_logical_server_retention_days"]
# }


# sql_logical_server_retention_days_metadata := {
#     "Policy Code": "PR-AZR-CLD-SQL-037",
#     "Type": "Cloud",
#     "Product": "AZR",
#     "Language": "",
#     "Policy Title": "Ensure SQL Server Threat Detection is Enabled and Retention Logs are greater than 90 days",
#     "Policy Description": "Azure SQL Database Threat Detection is a security intelligence feature built into the Azure SQL Database service. Working around the clock to learn, profile and detect anomalous database activities, Azure SQL Database Threat Detection identifies potential threats to the database. Security officers or other designated administrators can get an immediate notification about suspicious database activities as they occur. Each notification provides details of the suspicious activity and recommends how to further investigate and mitigate the threat.",
#     "Resource Type": "microsoft.sql/servers/securityalertpolicies",
#     "Policy Help URL": "",
#     "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
# }



# PR-AZR-CLD-SQL-038
#

default sql_server_retention_days = null

azure_attribute_absence["sql_server_retention_days"] {
    count([c | lower(input.resources[_].type) == "microsoft.sql/servers/securityalertpolicies"; c := 1]) == 0
}

# azure_attribute_absence["sql_server_retention_days"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
#     not resource.dependsOn
# }

azure_attribute_absence["sql_server_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not resource.properties.retentionDays
}

azure_issue["sql_server_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.sql/servers/securityalertpolicies";
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              to_number(resource.properties.retentionDays) > 90;
              c := 1]) == 0
}

azure_issue["sql_server_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.sql/servers/securityalertpolicies";
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              to_number(resource.properties.retentionDays) == 0;
              c := 1]) == 0
}

sql_server_retention_days {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    not azure_attribute_absence["sql_server_retention_days"]
    not azure_issue["sql_server_retention_days"]
}

sql_server_retention_days = false {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_attribute_absence["sql_server_retention_days"]
}

sql_server_retention_days = false {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_issue["sql_server_retention_days"]
}

sql_server_retention_days_err = "SQL Server security alert policy Retention Days are not greater than 90 days" {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_issue["sql_server_retention_days"]
} else = "Azure SQL security alert policy attribute 'retentionDays' is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_attribute_absence["sql_server_retention_days"]
}

sql_server_retention_days_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-038",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure SQL Server Threat Detection is Enabled and Retention Logs are greater than 90 days",
    "Policy Description": "Azure SQL Database Threat Detection is a security intelligence feature built into the Azure SQL Database service. Working around the clock to learn, profile and detect anomalous database activities, Azure SQL Database Threat Detection identifies potential threats to the database. Security officers or other designated administrators can get an immediate notification about suspicious database activities as they occur. Each notification provides details of the suspicious activity and recommends how to further investigate and mitigate the threat.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies"
}



# PR-AZR-CLD-SQL-039
# Not valid for cloud provider as cloud seperates all the child resources into seperate resource

# default sql_logical_server_disabled_alerts = null

# azure_attribute_absence["sql_logical_server_disabled_alerts"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers"
#     sql_resources := resource.resources[_]
#     lower(sql_resources.type) == "securityalertpolicies"
#     not sql_resources.properties.disabledAlerts
# }


# azure_issue["sql_logical_server_disabled_alerts"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers"
#     sql_resources := resource.resources[_]
#     lower(sql_resources.type) == "securityalertpolicies"
#     count(sql_resources.properties.disabledAlerts) > 0
# }


# sql_logical_server_disabled_alerts {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers"
#     sql_resources := resource.resources[_]
#     lower(sql_resources.type) == "securityalertpolicies"
#     not azure_attribute_absence["sql_logical_server_disabled_alerts"]
#     not azure_issue["sql_logical_server_disabled_alerts"]
# }


# sql_logical_server_disabled_alerts {
#     azure_attribute_absence["sql_logical_server_disabled_alerts"]
# }

# sql_logical_server_disabled_alerts = false {
#     azure_issue["sql_logical_server_disabled_alerts"]
# }

# sql_logical_server_disabled_alerts_err = "Azure SQL Server Security Alert Policy currently have one or more alert type in disabled alerts list" {
#     azure_issue["sql_logical_server_disabled_alerts"]
# }


# sql_logical_server_disabled_alerts_metadata := {
#     "Policy Code": "PR-AZR-CLD-SQL-039",
#     "Type": "Cloud",
#     "Product": "AZR",
#     "Language": "",
#     "Policy Title": "Azure SQL Server threat detection alerts should be enabled for all threat types",
#     "Policy Description": "Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification.<br><br>This policy identifies Azure SQL servers that have disabled the detection of one or more threat types. To protect your SQL Servers, as a best practice, enable ADS detection for all types of threats.",
#     "Resource Type": "microsoft.sql/servers/securityalertpolicies",
#     "Policy Help URL": "",
#     "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/securityalertpolicies"
# }



# PR-AZR-CLD-SQL-040
#

default sql_server_disabled_alerts = null

azure_attribute_absence["sql_server_disabled_alerts"] {
    count([c | lower(input.resources[_].type) == "microsoft.sql/servers/securityalertpolicies"; c := 1]) == 0
}

# azure_attribute_absence["sql_server_disabled_alerts"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
#     not resource.dependsOn
# }

azure_attribute_absence["sql_server_disabled_alerts"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/securityalertpolicies"
    not resource.properties.disabledAlerts
}

azure_issue["sql_server_disabled_alerts"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.sql/servers/securityalertpolicies";
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              count(resource.properties.disabledAlerts) > 0;
              c := 1]) > 0
}

sql_server_disabled_alerts {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    not azure_attribute_absence["sql_server_disabled_alerts"]
    not azure_issue["sql_server_disabled_alerts"]
}

sql_server_disabled_alerts {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_attribute_absence["sql_server_disabled_alerts"]
}

sql_server_disabled_alerts = false {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_issue["sql_server_disabled_alerts"]
}

sql_server_disabled_alerts_err = "Azure SQL Server Security Alert Policy currently have one or more alert type in disabled alerts list" {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_issue["sql_server_disabled_alerts"]
}

sql_server_disabled_alerts_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-040",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure SQL Server threat detection alerts should be enabled for all threat types",
    "Policy Description": "Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification.<br><br>This policy identifies Azure SQL servers that have disabled the detection of one or more threat types. To protect your SQL Servers, as a best practice, enable ADS detection for all types of threats.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/securityalertpolicies"
}