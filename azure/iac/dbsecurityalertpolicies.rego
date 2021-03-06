package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies

#
# PR-AZR-0054-ARM
#

default dbsec_threat_retention = null

azure_attribute_absence["dbsec_threat_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    not resource.properties.state
}

azure_issue["dbsec_threat_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    lower(resource.properties.state) != "enabled"
}

azure_issue["dbsec_threat_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    to_number(resource.properties.retentionDays) <= 90
}

dbsec_threat_retention {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases/securityalertpolicies"
    not azure_issue["dbsec_threat_retention"]
    not azure_attribute_absence["dbsec_threat_retention"]
}

dbsec_threat_retention = false {
    azure_issue["dbsec_threat_retention"]
}

dbsec_threat_retention = false {
    azure_attribute_absence["dbsec_threat_retention"]
}

dbsec_threat_retention_err = "Azure SQL DB with Threat Retention less than 91 days" {
    azure_issue["dbsec_threat_retention"]
}

dbsec_threat_retention_miss_err = "DB policy attribute state missing in the resource" {
    azure_attribute_absence["dbsec_threat_retention"]
}

dbsec_threat_retention_metadata := {
    "Policy Code": "PR-AZR-0054-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure SQL Database with Threat Retention less than or equals to 90 days",
    "Policy Description": "This policy identifies SQL Databases which have Threat Retention less than or equals to 90 days. Threat Logs can be used to check for anomalies and gives an understanding of suspected breaches or misuse of data and access. It is recommended to configure SQL database Threat Retention to be greater than 90 days.",
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
    not resource.properties.state
}

azure_issue["dbsec_threat_email"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    lower(resource.properties.state) != "enabled"
}

azure_issue["dbsec_threat_email"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    resource.properties.emailAccountAdmins != true
}

azure_issue["dbsec_threat_email"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    count(resource.properties.emailAddresses) == 0
}

dbsec_threat_email {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases/securityalertpolicies"
    not azure_issue["dbsec_threat_email"]
    not azure_attribute_absence["dbsec_threat_email"]
}

dbsec_threat_email = false {
    azure_issue["dbsec_threat_email"]
}

dbsec_threat_email = false {
    azure_attribute_absence["dbsec_threat_email"]
}

dbsec_threat_email_err = "Azure SQL DB with disabled Email service and co-administrators for Threat Detection" {
    azure_issue["dbsec_threat_email"]
}

dbsec_threat_email_miss_err = "DB policy attribute state missing in the resource" {
    azure_attribute_absence["dbsec_threat_email"]
}

dbsec_threat_email_metadata := {
    "Policy Code": "PR-AZR-0055-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure SQL Databases with disabled Email service and co-administrators for Threat Detection",
    "Policy Description": "This policy identifies SQL Databases which have disabled Email service and co-administrators for Threat Detection. Enable 'Email service and co-administrators' option to receive security alerts of any anomalous activities in SQL database. The alert notifications are sent to service and co-administrator email addresses so that they can mitigate any potential risks.",
    "Resource Type": "microsoft.sql/servers/databases/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies"
}

#
# PR-AZR-0061-ARM
# PR-AZR-0097-ARM
#

default dbsec_threat_alert = null

azure_attribute_absence["dbsec_threat_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    not resource.properties.state
}

azure_issue["dbsec_threat_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    lower(resource.properties.state) != "enabled"
}

azure_issue["dbsec_threat_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    count(resource.properties.disabledAlerts) > 0
}

dbsec_threat_alert {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases/securityalertpolicies"
    not azure_issue["dbsec_threat_alert"]
    not azure_attribute_absence["dbsec_threat_alert"]
}

dbsec_threat_alert = false {
    azure_issue["dbsec_threat_alert"]
}

dbsec_threat_alert = false {
    azure_attribute_absence["dbsec_threat_alert"]
}

dbsec_threat_alert_err = "Azure SQL Server threat detection alerts not enabled for all threat types" {
    azure_issue["dbsec_threat_alert"]
}

dbsec_threat_alert_miss_err = "DB policy attribute state missing in the resource" {
    azure_attribute_absence["dbsec_threat_alert"]
}

dbsec_threat_alert_metadata := {
    "Policy Code": "PR-AZR-0061-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure SQL Server threat detection alerts not enabled for all threat types",
    "Policy Description": "Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification._x005F_x000D_ _x005F_x000D_ This policy identifies Azure SQL servers that have disabled the detection of one or more threat types. To protect your SQL Servers, as a best practice, enable ADS detection for all types of threats.",
    "Resource Type": "microsoft.sql/servers/databases/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies"
}

#
# PR-AZR-0088-ARM
#

default sql_alert = null

azure_attribute_absence["sql_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    not resource.properties.state
}

azure_issue["sql_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    lower(resource.properties.state) != "enabled"
}

azure_issue["sql_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    not resource.properties.emailAccountAdmins
}

azure_issue["sql_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    resource.properties.emailAccountAdmins != true
}

sql_alert {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases/securityalertpolicies"
    not azure_issue["sql_alert"]
    not azure_attribute_absence["sql_alert"]
}

sql_alert = false {
    azure_issue["sql_alert"]
}

sql_alert = false {
    azure_attribute_absence["sql_alert"]
}

sql_alert_err = "Send alerts on field value on SQL Databases is misconfigured" {
    azure_issue["sql_alert"]
}

sql_alert_miss_err = "DB policy attribute state missing in the resource" {
    azure_attribute_absence["sql_alert"]
}

sql_alert_metadata := {
    "Policy Code": "PR-AZR-0097-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Threat Detection types on SQL databases is misconfigured",
    "Policy Description": "Ensure that Threat Detection types is set to All",
    "Resource Type": "microsoft.sql/servers/databases/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies"
}


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
    not azure_issue["dbsec_threat_off"]
    not azure_attribute_absence["dbsec_threat_off"]
}

dbsec_threat_off = false {
    azure_issue["dbsec_threat_off"]
}

dbsec_threat_off = false {
    azure_attribute_absence["dbsec_threat_off"]
}

dbsec_threat_off_err = "Threat Detection on SQL databases is set to Off" {
    azure_issue["dbsec_threat_off"]
}

dbsec_threat_off_miss_err = "DB policy attribute state missing in the resource" {
    azure_attribute_absence["dbsec_threat_off"]
}

dbsec_threat_off_metadata := {
    "Policy Code": "PR-AZR-0088-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Send alerts on field value on SQL Databases is misconfigured",
    "Policy Description": "Checks to ensure that an valid email address is set for Threat Detection alerts. The alerts are sent to this email address when any anomalous activities are detected on SQL databases.",
    "Resource Type": "microsoft.sql/servers/databases/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies"
}
