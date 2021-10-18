package rule

# https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances

#
# PR-GCP-GDF-SQLI-001
#

default sql_labels = null

gc_issue["sql_labels"] {
    resource := input.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    not resource.properties.settings.userLabels
}

gc_issue["sql_labels"] {
    resource := input.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    count(resource.properties.settings.userLabels) == 0
}

sql_labels {
    lower(input.resources[_].type) == "sqladmin.v1beta4.instance"
    not gc_issue["sql_labels"]
}

sql_labels = false {
    gc_issue["sql_labels"]
}

sql_labels_err = "GCP SQL Instances without any Label information" {
    gc_issue["sql_labels"]
}

sql_labels_metadata := {
    "Policy Code": "PR-GCP-GDF-SQLI-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP SQL Instances without any Label information",
    "Policy Description": "This policy identifies the SQL DB instance which does not have any Labels. Labels can be used for easy identification and searches.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}

#
# PR-GCP-GDF-SQLI-002
#

default sql_binary_logs = null


gc_attribute_absence["sql_binary_logs"] {
    resource := input.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    not resource.properties.databaseVersion
}

gc_issue["sql_binary_logs"] {
    resource := input.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    contains(lower(resource.properties.databaseVersion), "mysql")
    not resource.properties.settings.backupConfiguration.binaryLogEnabled
}

sql_binary_logs {
    lower(input.resources[_].type) == "sqladmin.v1beta4.instance"
    not gc_issue["sql_binary_logs"]
    not gc_attribute_absence["sql_binary_logs"]
}

sql_binary_logs = false {
    gc_issue["sql_binary_logs"]
}

sql_binary_logs = false {
    gc_attribute_absence["sql_binary_logs"]
}

sql_binary_logs_err = "SQL DB Instance backup Binary logs configuration is not enabled" {
    gc_issue["sql_binary_logs"]
}

sql_binary_logs_miss_err = "GCP DB Instance attribute databaseVersion missing in the resource" {
    gc_attribute_absence["sql_binary_logs"]
}

sql_binary_logs_metadata := {
    "Policy Code": "PR-GCP-GDF-SQLI-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "SQL DB Instance backup Binary logs configuration is not enabled",
    "Policy Description": "Checks to verify that the configuration for automated backup of Binary logs is enabled. _x005F_x000D_         Restoring from a backup reverts your instance to its state at the backup's creation time. Enabling automated backups creates backup during the scheduled backup window.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}

#
# PR-GCP-GDF-SQLI-003
#

default sql_backup = null


gc_attribute_absence["sql_backup"] {
    resource := input.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    not resource.properties.settings.backupConfiguration
}

gc_issue["sql_backup"] {
    resource := input.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    not resource.properties.settings.backupConfiguration.enabled
}

sql_backup {
    lower(input.resources[_].type) == "sqladmin.v1beta4.instance"
    not gc_issue["sql_backup"]
    not gc_attribute_absence["sql_backup"]
}

sql_backup = false {
    gc_issue["sql_backup"]
}

sql_backup = false {
    gc_attribute_absence["sql_backup"]
}

sql_backup_err = "SQL DB instance backup configuration is not enabled" {
    gc_issue["sql_backup"]
}

sql_backup_miss_err = "GCP DB Instance attribute backupConfiguration missing in the resource" {
    gc_attribute_absence["sql_backup"]
}

sql_backup_metadata := {
    "Policy Code": "PR-GCP-GDF-SQLI-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "SQL DB instance backup configuration is not enabled",
    "Policy Description": "Checks to verify that the configuration for automated backups is enabled. _x005F_x000D_         Restoring from a backup reverts your instance to its state at the backup's creation time. Enabling automated backups creates backup during the scheduled backup window.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}

#
# PR-GCP-GDF-SQLI-004
#

default sql_ssl = null


gc_attribute_absence["sql_ssl"] {
    resource := input.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    not resource.properties.settings.ipConfiguration.requireSsl
}

gc_issue["sql_ssl"] {
    resource := input.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    resource.properties.settings.ipConfiguration.requireSsl != true
}

sql_ssl {
    lower(input.resources[_].type) == "sqladmin.v1beta4.instance"
    not gc_issue["sql_ssl"]
    not gc_attribute_absence["sql_ssl"]
}

sql_ssl = false {
    gc_issue["sql_ssl"]
}

sql_ssl = false {
    gc_attribute_absence["sql_ssl"]
}

sql_ssl_err = "SQL Instances do not have SSL configured" {
    gc_issue["sql_ssl"]
}

sql_ssl_miss_err = "GCP DB Instance attribute ipConfiguration.requireSsl missing in the resource" {
    gc_attribute_absence["sql_ssl"]
}

sql_ssl_metadata := {
    "Policy Code": "PR-GCP-GDF-SQLI-004",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "SQL Instances do not have SSL configured",
    "Policy Description": "Checks to verify that the SSL configuration for the SQL instance is valid with an unexpired SSL certificate._x005F_x000D_         Cloud SQL supports connecting to an instance using the Secure Socket Layer (SSL) protocol. If you are not connecting to an instance by using Cloud SQL Proxy, you should use SSL, so that the data you send and receive from Google Cloud SQL is secure.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}

#
# PR-GCP-GDF-SQLI-005
#

default sql_exposed = null


gc_attribute_absence["sql_exposed"] {
    resource := input.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    not resource.properties.settings.ipConfiguration.authorizedNetworks
}

gc_issue["sql_exposed"] {
    resource := input.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    resource.properties.settings.ipConfiguration.authorizedNetworks[_] == "0.0.0.0"
}

gc_issue["sql_exposed"] {
    resource := input.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    resource.properties.settings.ipConfiguration.authorizedNetworks[_] == "0.0.0.0/0"
}

gc_issue["sql_exposed"] {
    resource := input.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    resource.properties.settings.ipConfiguration.authorizedNetworks[_] == "::/0"
}

sql_exposed {
    lower(input.resources[_].type) == "sqladmin.v1beta4.instance"
    not gc_issue["sql_exposed"]
    not gc_attribute_absence["sql_exposed"]
}

sql_exposed = false {
    gc_issue["sql_exposed"]
}

sql_exposed = false {
    gc_attribute_absence["sql_exposed"]
}

sql_exposed_err = "SQL Instances with network authorization exposing them to the Internet" {
    gc_issue["sql_exposed"]
}

sql_exposed_miss_err = "GCP DB Instance attribute ipConfiguration.authorizedNetworks missing in the resource" {
    gc_attribute_absence["sql_exposed"]
}

sql_exposed_metadata := {
    "Policy Code": "PR-GCP-GDF-SQLI-005",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "SQL Instances with network authorization exposing them to the Internet",
    "Policy Description": "Checks to verify that the SQL instance should not have any authorization to allow network traffic to the internet.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}

