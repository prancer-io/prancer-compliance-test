package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies


#
# PR-AZR-0096-ARM
#

default dbsec_threat_off = null

azure_attribute_absence["dbsec_threat_off"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    not resource.properties.state
}

azure_issue["dbsec_threat_off"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    lower(resource.properties.state) != "enabled"
}

dbsec_threat_off {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases/securityalertpolicies"
    not azure_attribute_absence["dbsec_threat_off"]
    not azure_issue["dbsec_threat_off"]
}

dbsec_threat_off = false {
    azure_issue["dbsec_threat_off"]
}

dbsec_threat_off = false {
    azure_attribute_absence["dbsec_threat_off"]
}

dbsec_threat_off_err = "SQL Databases security alert policy is currently not enabled" {
    azure_issue["dbsec_threat_off"]
}

dbsec_threat_off_miss_err = "SQL Databases securityAlertPolicies attribute 'state' is missing from the resource" {
    azure_attribute_absence["dbsec_threat_off"]
}

dbsec_threat_off_metadata := {
    "Policy Code": "PR-AZR-0088-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "SQL Databases should have security alert policies enabled",
    "Policy Description": "Checks to ensure that security alert policy is enabled on SQL databases. The alerts are sent to configured email address when any anomalous activities are detected on SQL databases.",
    "Resource Type": "microsoft.sql/servers/databases/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies"
}


#
# PR-AZR-0054-ARM
#

default dbsec_threat_retention = null

azure_attribute_absence["dbsec_threat_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    not resource.properties.retentionDays
}

azure_issue["dbsec_threat_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    to_number(resource.properties.retentionDays) <= 90
}

dbsec_threat_retention {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases/securityalertpolicies"
    not azure_attribute_absence["dbsec_threat_retention"]
    not azure_issue["dbsec_threat_retention"]
}

dbsec_threat_retention = false {
    azure_issue["dbsec_threat_retention"]
}

dbsec_threat_retention = false {
    azure_attribute_absence["dbsec_threat_retention"]
}

dbsec_threat_retention_err = "Azure SQL Database security alert policies retention is currently not configured for more than 90 days" {
    azure_issue["dbsec_threat_retention"]
}

dbsec_threat_retention_miss_err = "Azure SQL Database security alert policies retention attribute 'retentionDays' is missing from the resource" {
    azure_attribute_absence["dbsec_threat_retention"]
}

dbsec_threat_retention_metadata := {
    "Policy Code": "PR-AZR-0054-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure SQL Database security alert policies retention should be configured for more than 90 days",
    "Policy Description": "This policy identifies SQL Databases which have security alert policies retention set less than or equals to 90 days. Threat Logs can be used to check for anomalies and gives an understanding of suspected breaches or misuse of data and access. It is recommended to configure SQL database Threat Retention to be greater than 90 days.",
    "Resource Type": "microsoft.sql/servers/databases/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies"
}

#
# PR-AZR-0055-ARM
#

default dbsec_threat_email = null

azure_attribute_absence["dbsec_threat_email"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    not resource.properties.emailAccountAdmins
}

azure_attribute_absence["dbsec_threat_email"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    not resource.properties.emailAddresses
}

azure_issue["dbsec_threat_email"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/da000tabases/securityalertpolicies"
    resource.properties.emailAccountAdmins != true
}

azure_issue["dbsec_threat_email"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    count(resource.properties.emailAddresses) == 0
}

dbsec_threat_email {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases/securityalertpolicies"
    not azure_attribute_absence["dbsec_threat_email"]
    not azure_issue["dbsec_threat_email"]
}

dbsec_threat_email = false {
    azure_issue["dbsec_threat_email"]
}

dbsec_threat_email = false {
    azure_attribute_absence["dbsec_threat_email"]
}

dbsec_threat_email_err = "Azure SQL Databases security alert policy is currently not configured to sent alert to the account administrators via email" {
    azure_issue["dbsec_threat_email"]
}

dbsec_threat_email_miss_err = "Azure SQL Databases security alert policy attribute 'emailAccountAdmins' or 'emailAddresses' is missing from the resource" {
    azure_attribute_absence["dbsec_threat_email"]
}

dbsec_threat_email_metadata := {
    "Policy Code": "PR-AZR-0055-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure SQL Databases Security Alert Policy should be configured to send alert to the account administrators via email",
    "Policy Description": "This policy identifies SQL Databases which has email account admins disabled and there is no email address provided where the alert supposed to be sent.",
    "Resource Type": "microsoft.sql/servers/databases/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies"
}

#
# PR-AZR-0061-ARM
#

default dbsec_threat_alert = null

azure_attribute_absence["dbsec_threat_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    not resource.properties.disabledAlerts
}

azure_issue["dbsec_threat_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    count(resource.properties.disabledAlerts) > 0
}

dbsec_threat_alert {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases/securityalertpolicies"
    not azure_attribute_absence["dbsec_threat_alert"]
    not azure_issue["dbsec_threat_alert"]
}

dbsec_threat_alert = false {
    azure_issue["dbsec_threat_alert"]
}

dbsec_threat_alert {
    azure_attribute_absence["dbsec_threat_alert"]
}

dbsec_threat_alert_err = "Azure SQL Server Security Alert Policy currently have one or more alert type in disabled alerts list" {
    azure_issue["dbsec_threat_alert"]
}

dbsec_threat_alert_miss_err = "Azure SQL Server Security Alert Policy attribute 'disabledAlerts' is missing from the resource. Which is fine" {
    azure_attribute_absence["dbsec_threat_alert"]
}

dbsec_threat_alert_metadata := {
    "Policy Code": "PR-AZR-0061-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure SQL Server Security Alert Policy should not disable any type of alerts",
    "Policy Description": "Ensure that Azure SQL Server Security Alert Policy is not excluding any type of alerts",
    "Resource Type": "microsoft.sql/servers/databases/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies"
}


