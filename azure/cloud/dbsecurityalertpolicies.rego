package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies


#
# PR-AZR-CLD-SQL-017
#

default dbsec_threat_off = null

azure_attribute_absence["dbsec_threat_off"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.state
}

source_path[{"dbsec_threat_off":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.state
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","state"]]
    }
}

azure_issue["dbsec_threat_off"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    lower(sql_resources.properties.state) != "enabled"
}

source_path[{"dbsec_threat_off":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    lower(sql_resources.properties.state) != "enabled"
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","state"]]
    }
}

dbsec_threat_off {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not azure_attribute_absence["dbsec_threat_off"]
    not azure_issue["dbsec_threat_off"]
}

dbsec_threat_off = false {
    azure_issue["dbsec_threat_off"]
}

dbsec_threat_off = false {
    azure_attribute_absence["dbsec_threat_off"]
}

dbsec_threat_off_err = "SQL Databases securityAlertPolicies attribute 'state' is missing from the resource" {
    azure_attribute_absence["dbsec_threat_off"]
} else = "SQL Databases security alert policy is currently not enabled" {
    azure_issue["dbsec_threat_off"]
}


dbsec_threat_off_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-017",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "SQL Databases should have security alert policies enabled",
    "Policy Description": "SQL Threat Detection provides a new layer of security, which enables customers to detect and respond to potential threats as they occur by providing security alerts on anomalous activities. Users will receive an alert upon suspicious database activities, potential vulnerabilities, and SQL injection attacks, as well as anomalous database access patterns. SQL Threat Detection alerts provide details of suspicious activity and recommend action on how to investigate and mitigate the threat.",
    "Resource Type": "microsoft.sql/servers/databases/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies"
}


#
# PR-AZR-CLD-SQL-018
#

default dbsec_threat_retention = null

azure_attribute_absence["dbsec_threat_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.retentionDays
}

source_path[{"dbsec_threat_retention":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.retentionDays
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","retentionDays"]]
    }
}


azure_issue["dbsec_threat_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    to_number(sql_resources.properties.retentionDays) <= 90
}


source_path[{"dbsec_threat_retention":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    to_number(sql_resources.properties.retentionDays) <= 90
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","retentionDays"]]
    }
}

dbsec_threat_retention {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases"
    resource := input.resources[_]
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not azure_attribute_absence["dbsec_threat_retention"]
    not azure_issue["dbsec_threat_retention"]
}

dbsec_threat_retention = false {
    azure_issue["dbsec_threat_retention"]
}

dbsec_threat_retention = false {
    azure_attribute_absence["dbsec_threat_retention"]
}

dbsec_threat_retention_err = "Azure SQL Database security alert policies thread retention is currently not configured for more than 90 days" {
    azure_issue["dbsec_threat_retention"]
}

dbsec_threat_retention_miss_err = "Azure SQL Database security alert policies retention attribute 'retentionDays' is missing from the resource" {
    azure_attribute_absence["dbsec_threat_retention"]
}

dbsec_threat_retention_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-018",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure SQL Database security alert policies thread retention should be configured for more than 90 days",
    "Policy Description": "This policy identifies SQL Databases which have security alert policies retention set less than or equals to 90 days. Threat Logs can be used to check for anomalies and gives an understanding of suspected breaches or misuse of data and access. It is recommended to configure SQL database Threat Retention to be greater than 90 days.",
    "Resource Type": "microsoft.sql/servers/databases/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies"
}

#
# PR-AZR-CLD-SQL-019
#

default dbsec_threat_email = null


azure_attribute_absence["dbsec_threat_email"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.emailAddresses
}

source_path[{"dbsec_threat_email":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.emailAddresses
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","emailAddresses"]]
    }
}

azure_issue["dbsec_threat_email"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    count(sql_resources.properties.emailAddresses) == 0  
}

source_path[{"dbsec_threat_email":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    count(sql_resources.properties.emailAddresses) == 0  
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","emailAddresses"]]
    }
}

dbsec_threat_email {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases"
    resource := input.resources[_]
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not azure_attribute_absence["dbsec_threat_email"]
    not azure_issue["dbsec_threat_email"]
}


dbsec_threat_email = false {
    azure_attribute_absence["dbsec_threat_email"]
}


dbsec_threat_email = false {
    azure_issue["dbsec_threat_email"]
}


dbsec_threat_email_err = "Azure SQL Databases security alert policy attribute 'emailAccountAdmins' or 'emailAddresses' is missing from the resource" {
    azure_attribute_absence["dbsec_threat_email"]
} else = "Azure SQL Databases security alert policy is currently not configured to sent alert to the account administrators via email" {
    azure_issue["dbsec_threat_email"]
}


dbsec_threat_email_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-019",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure SQL Databases Security Alert Policy should be configured to send alert to the account administrators and configured email addresses",
    "Policy Description": "Checks to ensure that an valid email address is set for Threat Detection alerts. The alerts are sent to this email address when any anomalous activities are detected on SQL databases.",
    "Resource Type": "microsoft.sql/servers/databases/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies"
}

#
# PR-AZR-CLD-SQL-020
#

default dbsec_threat_alert = null

azure_attribute_absence["dbsec_threat_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.disabledAlerts
}

source_path[{"dbsec_threat_email":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.disabledAlerts
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","disabledAlerts"]]
    }
}

azure_issue["dbsec_threat_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    count(sql_resources.properties.disabledAlerts) > 0
}

source_path[{"dbsec_threat_email":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    count(sql_resources.properties.disabledAlerts) > 0
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","disabledAlerts"]]
    }
}


dbsec_threat_alert {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not azure_attribute_absence["dbsec_threat_alert"]
    not azure_issue["dbsec_threat_alert"]
}


dbsec_threat_alert {
    azure_attribute_absence["dbsec_threat_alert"]
}

dbsec_threat_alert = false {
    azure_issue["dbsec_threat_alert"]
}

dbsec_threat_alert_err = "Azure SQL Server Security Alert Policy currently have one or more alert type in disabled alerts list" {
    azure_issue["dbsec_threat_alert"]
}


dbsec_threat_alert_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-020",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure SQL Server threat detection alerts should be enabled for all threat types",
    "Policy Description": "Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification.<br><br>This policy identifies Azure SQL servers that have disabled the detection of one or more threat types. To protect your SQL Servers, as a best practice, enable ADS detection for all types of threats.",
    "Resource Type": "microsoft.sql/servers/databases/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies"
}

#
# PR-AZR-CLD-SQL-021
#

default sql_alert = null

azure_issue["sql_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.emailAccountAdmins
}

source_path[{"sql_alert":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.emailAccountAdmins
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","emailAccountAdmins"]]
    }
}

azure_issue["sql_alert"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    sql_resources.properties.emailAccountAdmins != true
}


source_path[{"sql_alert":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "securityalertpolicies"
    not sql_resources.properties.emailAccountAdmins
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","emailAccountAdmins"]]
    }
}

sql_alert {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "securityalertpolicies"
    not azure_attribute_absence["sql_alert"]
    not azure_issue["sql_alert"]
}


sql_alert = false {
    azure_attribute_absence["sql_alert"]
}


sql_alert = false {
    azure_issue["sql_alert"]
}

sql_alert_err = "microsoft.sql/servers/databases/securityalertpolicies property 'emailAccountAdmins' need to be exist. Its missing from the resource." {
    azure_attribute_absence["sql_alert"]
} else = "Threat Detection alert currently is not configured to sent notification to the sql server account administrators" {
    azure_issue["sql_alert"]
}

sql_alert_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-021",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Threat Detection alert should be configured to sent notification to the sql server account administrators",
    "Policy Description": "Ensure that threat detection alert is configured to sent notification to the sql server account administrators",
    "Resource Type": "microsoft.sql/servers/databases/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies"
}


