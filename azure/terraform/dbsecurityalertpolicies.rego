package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy
#
# PR-AZR-0054-TRF
#

default dbsec_threat_retention = null

azure_attribute_absence["dbsec_threat_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_security_alert_policy"
    not resource.properties.retention_days
}

azure_issue["dbsec_threat_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_security_alert_policy"
    to_number(resource.properties.retention_days) <= 90
}

dbsec_threat_retention {
    lower(input.resources[_].type) == "azurerm_mssql_server_security_alert_policy"
    not azure_attribute_absence["dbsec_threat_retention"]
    not azure_issue["dbsec_threat_retention"]
}

dbsec_threat_retention = false {
    azure_attribute_absence["dbsec_threat_retention"]
}

dbsec_threat_retention = false {
    azure_issue["dbsec_threat_retention"]
}

dbsec_threat_retention_err = "azurerm_mssql_server_security_alert_policy property 'retention_days' need to be exist. Its missing from the resource. Please set the value to '91' after property addition." {
    azure_attribute_absence["dbsec_threat_retention"]
} else = "Azure SQL Database security alert policies thread retention is currently not configured for more than 90 days" {
    azure_issue["dbsec_threat_retention"]
}

dbsec_threat_retention_metadata := {
    "Policy Code": "PR-AZR-0054-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure SQL Database security alert policies thread retention should be configured for more than 90 days",
    "Policy Description": "This policy identifies SQL Databases which have Threat Retention less than or equals to 90 days. Threat Logs can be used to check for anomalies and gives an understanding of suspected breaches or misuse of data and access. It is recommended to configure SQL database Threat Retention to be greater than 90 days.",
    "Resource Type": "azurerm_mssql_server_security_alert_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy"
}

#
# PR-AZR-0055-TRF
#

default dbsec_threat_email = null

azure_attribute_absence["dbsec_threat_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_security_alert_policy"
    not resource.properties.email_account_admins
}

azure_attribute_absence["dbsec_threat_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_security_alert_policy"
    not resource.properties.email_addresses
}

azure_issue["dbsec_threat_email"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_security_alert_policy"
    resource.properties.email_account_admins != true
}

azure_issue["dbsec_threat_email"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_security_alert_policy"
    count(resource.properties.email_addresses) == 0
}

dbsec_threat_email {
    lower(input.resources[_].type) == "azurerm_mssql_server_security_alert_policy"
    not azure_attribute_absence["dbsec_threat_email"]
    not azure_issue["dbsec_threat_email"]
}

dbsec_threat_email = false {
    azure_attribute_absence["dbsec_threat_email"]
}

dbsec_threat_email = false {
    azure_issue["dbsec_threat_email"]
}

dbsec_threat_email_err = "azurerm_mssql_server_security_alert_policy property 'email_account_admins' and 'email_addresses' need to be exist. Those are missing from the resource." {
    azure_attribute_absence["dbsec_threat_email"]
} else = "Azure SQL Databases security alert policy is currently not configured to sent alert to the account administrators via email" {
    azure_issue["dbsec_threat_email"]
}

dbsec_threat_email_metadata := {
    "Policy Code": "PR-AZR-0055-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure SQL Databases Security Alert Policy should be configured to send alert to the account administrators and configured email addresses",
    "Policy Description": "Checks to ensure that an valid email address is set for Threat Detection alerts. The alerts are sent to this email address when any anomalous activities are detected on SQL databases.",
    "Resource Type": "azurerm_mssql_server_security_alert_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy"
}

#
# PR-AZR-0061-TRF
#

default dbsec_threat_alert = null

azure_attribute_absence["dbsec_threat_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_security_alert_policy"
    not resource.properties.disabled_alerts
}

azure_issue["dbsec_threat_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_security_alert_policy"
    count(resource.properties.disabled_alerts) > 0
}

dbsec_threat_alert {
    lower(input.resources[_].type) == "azurerm_mssql_server_security_alert_policy"
    not azure_attribute_absence["dbsec_threat_alert"]
    not azure_issue["dbsec_threat_alert"]
}

dbsec_threat_alert {
    azure_attribute_absence["dbsec_threat_alert"]
}

dbsec_threat_alert = false {
    azure_issue["dbsec_threat_alert"]
}

dbsec_threat_alert_err = "Azure SQL Server threat detection alerts not enabled for all threat types" {
    azure_issue["dbsec_threat_alert"]
}

dbsec_threat_alert_metadata := {
    "Policy Code": "PR-AZR-0061-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure SQL Server threat detection alerts should be enabled for all threat types",
    "Policy Description": "Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification._x005F_x000D_ _x005F_x000D_ This policy identifies Azure SQL servers that have disabled the detection of one or more threat types. To protect your SQL Servers, as a best practice, enable ADS detection for all types of threats.",
    "Resource Type": "azurerm_mssql_server_security_alert_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy"
}

#
# PR-AZR-0097-TRF
#

default sql_alert = null

azure_issue["sql_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_security_alert_policy"
    not resource.properties.email_account_admins
}

azure_issue["sql_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_security_alert_policy"
    resource.properties.email_account_admins != true
}

sql_alert {
    lower(input.resources[_].type) == "azurerm_mssql_server_security_alert_policy"
    not azure_attribute_absence["sql_alert"]
    not azure_issue["sql_alert"]
}

sql_alert = false {
    azure_attribute_absence["sql_alert"]
}

sql_alert = false {
    azure_issue["sql_alert"]
}

sql_alert_err = "azurerm_mssql_server_security_alert_policy property 'email_account_admins' need to be exist. Its missing from the resource." {
    azure_attribute_absence["sql_alert"]
} else = "Send alerts on field value on SQL Databases is misconfigured" {
    azure_issue["sql_alert"]
}

sql_alert_metadata := {
    "Policy Code": "PR-AZR-0097-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Threat Detection alert should be configured to sent notification to the sql server account administrators",
    "Policy Description": "Ensure that threat detection alert is configured to sent notification to the sql server account administrators",
    "Resource Type": "azurerm_mssql_server_security_alert_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy"
}

#
# PR-AZR-0096-TRF
#

default dbsec_threat_off = null

azure_attribute_absence["dbsec_threat_off"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_security_alert_policy"
    not resource.properties.state
}

azure_issue["dbsec_threat_off"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_security_alert_policy"
    lower(resource.properties.state) != "enabled"
}

dbsec_threat_off {
    lower(input.resources[_].type) == "azurerm_mssql_server_security_alert_policy"
    not azure_attribute_absence["dbsec_threat_off"]
    not azure_issue["dbsec_threat_off"]
}

dbsec_threat_off = false {
    azure_attribute_absence["dbsec_threat_off"]
}

dbsec_threat_off = false {
    azure_issue["dbsec_threat_off"]
}

dbsec_threat_off_err = "azurerm_mssql_server_security_alert_policy property 'state' is missing from the resource. Set the value to 'Enabled' after property addition." {
    azure_attribute_absence["dbsec_threat_off"]
} else = "SQL Databases security alert policy is currently not enabled" {
    azure_issue["dbsec_threat_off"]
}

dbsec_threat_off_metadata := {
    "Policy Code": "PR-AZR-0096-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "SQL Databases should have security alert policies enabled",
    "Policy Description": "SQL Threat Detection provides a new layer of security, which enables customers to detect and respond to potential threats as they occur by providing security alerts on anomalous activities. Users will receive an alert upon suspicious database activities, potential vulnerabilities, and SQL injection attacks, as well as anomalous database access patterns. SQL Threat Detection alerts provide details of suspicious activity and recommend action on how to investigate and mitigate the threat.",
    "Resource Type": "azurerm_mssql_server_security_alert_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy"
}
