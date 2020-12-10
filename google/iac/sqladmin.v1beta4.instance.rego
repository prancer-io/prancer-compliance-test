package rule

# https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances

#
# PR-GCP-0062-GDF
#

default sql_labels = null

gc_issue["sql_labels"] {
    resource := input.json.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    not resource.properties.settings.userLabels
}

gc_issue["sql_labels"] {
    resource := input.json.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    count(resource.properties.settings.userLabels) == 0
}

sql_labels {
    lower(input.json.resources[_].type) == "sqladmin.v1beta4.instance"
    not gc_issue["sql_labels"]
}

sql_labels = false {
    gc_issue["sql_labels"]
}

sql_labels_err = "GCP SQL Instances without any Label information" {
    gc_issue["sql_labels"]
}

#
# PR-GCP-0080-GDF
#

default sql_binary_logs = null


gc_attribute_absence["sql_binary_logs"] {
    resource := input.json.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    not resource.properties.databaseVersion
}

gc_issue["sql_binary_logs"] {
    resource := input.json.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    contains(lower(resource.properties.databaseVersion), "mysql")
    not resource.properties.settings.backupConfiguration.binaryLogEnabled
}

sql_binary_logs {
    lower(input.json.resources[_].type) == "sqladmin.v1beta4.instance"
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

#
# PR-GCP-0081-GDF
#

default sql_backup = null


gc_attribute_absence["sql_backup"] {
    resource := input.json.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    not resource.properties.settings.backupConfiguration
}

gc_issue["sql_backup"] {
    resource := input.json.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    not resource.properties.settings.backupConfiguration.enabled
}

sql_backup {
    lower(input.json.resources[_].type) == "sqladmin.v1beta4.instance"
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

#
# PR-GCP-0082-GDF
#

default sql_ssl = null


gc_attribute_absence["sql_ssl"] {
    resource := input.json.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    not resource.properties.settings.ipConfiguration.requireSsl
}

gc_issue["sql_ssl"] {
    resource := input.json.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    resource.properties.settings.ipConfiguration.requireSsl != true
}

sql_ssl {
    lower(input.json.resources[_].type) == "sqladmin.v1beta4.instance"
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

#
# PR-GCP-0083-GDF
#

default sql_exposed = null


gc_attribute_absence["sql_exposed"] {
    resource := input.json.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    not resource.properties.settings.ipConfiguration.authorizedNetworks
}

gc_issue["sql_exposed"] {
    resource := input.json.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    resource.properties.settings.ipConfiguration.authorizedNetworks[_] == "0.0.0.0"
}

gc_issue["sql_exposed"] {
    resource := input.json.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    resource.properties.settings.ipConfiguration.authorizedNetworks[_] == "0.0.0.0/0"
}

gc_issue["sql_exposed"] {
    resource := input.json.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    resource.properties.settings.ipConfiguration.authorizedNetworks[_] == "::/0"
}

sql_exposed {
    lower(input.json.resources[_].type) == "sqladmin.v1beta4.instance"
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

