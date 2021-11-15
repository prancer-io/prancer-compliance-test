package rule

# https://docs.microsoft.com/en-us/rest/api/sql/2020-08-01-preview/server-security-alert-policies/get


# PR-AZR-SQL-031

default sql_server_alert = null

azure_attribute_absence["sql_server_alert"] {
    not input.properties.state
}


azure_sql_security_alert_disabled["sql_server_alert"] {
    lower(input.properties.state) == "disabled"
}


sql_server_alert {
    not azure_attribute_absence["sql_server_alert"]
    not azure_sql_security_alert_disabled["sql_server_alert"]
}

sql_server_alert = false {
    azure_attribute_absence["sql_server_alert"]
}

sql_server_alert = false {
    azure_sql_security_alert_disabled["sql_server_alert"]
}


sql_server_alert_err = "securityAlertPolicies property 'state' is missing from the resource" {
    azure_attribute_absence["sql_server_alert"]
} else = "Security alert is currently not enabled on SQL Server" {
    azure_sql_security_alert_disabled["sql_server_alert"]
}

sql_server_alert_metadata := {
    "Policy Code": "PR-AZR-SQL-031",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Security Alert is enabled on Azure SQL Server",
    "Policy Description": "Advanced data security should be enabled on your SQL servers.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/sql/2020-08-01-preview/server-security-alert-policies/get"
}



# PR-AZR-SQL-032

default sql_managed_instance_alert = null


azure_attribute_absence["sql_managed_instance_alert"] {
    not input.properties.state
}


azure_sql_security_alert_disabled["sql_managed_instance_alert"] {
    lower(input.properties.state) == "disabled"
}


sql_managed_instance_alert {
    not azure_attribute_absence["sql_managed_instance_alert"]
    not azure_sql_security_alert_disabled["sql_managed_instance_alert"]
}

sql_managed_instance_alert = false {
    azure_attribute_absence["sql_managed_instance_alert"]
}

sql_managed_instance_alert = false {
    azure_sql_security_alert_disabled["sql_managed_instance_alert"]
}


sql_managed_instance_alert_err = "securityAlertPolicies property 'state' is missing from the resource" {
    azure_attribute_absence["sql_managed_instance_alert"]
} else = "Security alert is currently not enabled on SQL managed instance resource." {
    azure_sql_security_alert_disabled["sql_managed_instance_alert"]
}

sql_managed_instance_alert_metadata := {
    "Policy Code": "PR-AZR-SQL-032",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Advanced data security should be enabled on your SQL managed instance.",
    "Policy Description": "Advanced data security should be enabled on your SQL managed instance.",
    "Resource Type": "microsoft.sql/managedinstances/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/sql/2020-08-01-preview/managed-server-security-alert-policies/get"
}


# PR-AZR-SQL-034

default sql_server_email_account = null

azure_issue["sql_server_email_account"] {
    not input.properties.emailAccountAdmins
}

azure_issue["sql_server_email_account"] {
    input.properties.emailAccountAdmins != true
}


sql_server_email_account {
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
    "Policy Code": "PR-AZR-SQL-034",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server",
    "Policy Description": "VA scan reports and alerts will be sent to admins and subscription owners by enabling setting 'Also send email notifications to admins and subscription owners'. This may help in reducing time required for identifying risks and taking corrective measures.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/sql/2020-08-01-preview/server-security-alert-policies/get"
}

# PR-AZR-SQL-036

default sql_server_email_addressess = null


azure_attribute_absence["sql_server_email_addressess"] {
    not input.properties.emailAddresses
}


azure_issue["sql_server_email_addressess"] {
    count(input.properties.emailAddresses) == 0  
}


sql_server_email_addressess {
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
    "Policy Code": "PR-AZR-SQL-036",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure SQL Security Alert Policy should be configured to send alerts to the account administrators and configured email addresses",
    "Policy Description": "Provide the email address where alerts will be sent when anomalous activities are detected on SQL servers.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/sql/2020-08-01-preview/server-security-alert-policies/get"
}



# PR-AZR-SQL-038

default sql_server_retention_days = null


azure_attribute_absence["sql_server_retention_days"] {
    not input.properties.retentionDays
}

azure_issue["sql_server_retention_days"] {
    to_number(input.properties.retentionDays) == 0  
}

azure_issue["sql_server_retention_days"] {
    to_number(input.properties.retentionDays) >= 90 
}

sql_server_retention_days {
    not azure_attribute_absence["sql_server_retention_days"]
    azure_issue["sql_server_retention_days"]
}


sql_server_retention_days = false {
    azure_attribute_absence["sql_server_retention_days"]
}


sql_server_retention_days = false {
    not azure_issue["sql_server_retention_days"]
}


sql_server_retention_days_err = "Azure SQL security alert policy attribute 'retentionDays' is missing from the resource" {
    azure_attribute_absence["sql_server_retention_days"]
} else = "SQL Server security alert policy Retention Days are not greater than 90 days" {
    not azure_issue["sql_server_retention_days"]
}


sql_server_retention_days_metadata := {
    "Policy Code": "PR-AZR-SQL-038",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure SQL Server Threat Detection is Enabled and Retention Logs are greater than 90 days",
    "Policy Description": "Azure SQL Database Threat Detection is a security intelligence feature built into the Azure SQL Database service. Working around the clock to learn, profile and detect anomalous database activities, Azure SQL Database Threat Detection identifies potential threats to the database. Security officers or other designated administrators can get an immediate notification about suspicious database activities as they occur. Each notification provides details of the suspicious activity and recommends how to further investigate and mitigate the threat.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/sql/2020-08-01-preview/server-security-alert-policies/get"
}


# PR-AZR-SQL-040

default sql_server_disabled_alerts = null

azure_attribute_absence["sql_server_disabled_alerts"] {
    not input.properties.disabledAlerts
}

azure_issue["sql_server_disabled_alerts"] {
    count(input.properties.disabledAlerts) > 0
}


sql_server_disabled_alerts {
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
    "Policy Code": "PR-AZR-SQL-040",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure SQL Server threat detection alerts should be enabled for all threat types",
    "Policy Description": "Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification.<br><br>This policy identifies Azure SQL servers that have disabled the detection of one or more threat types. To protect your SQL Servers, as a best practice, enable ADS detection for all types of threats.",
    "Resource Type": "microsoft.sql/servers/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/sql/2020-08-01-preview/server-security-alert-policies/get"
}