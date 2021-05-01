package rule

# https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances

#
# PR-GCP-0062-TRF
#

default sql_labels = null

gc_issue["sql_labels"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    not resource.properties.settings.userLabels
}

gc_issue["sql_labels"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    count(resource.properties.settings.userLabels) == 0
}

sql_labels {
    lower(input.resources[_].type) == "google_sql_database_instance"
    not gc_issue["sql_labels"]
}

sql_labels = false {
    gc_issue["sql_labels"]
}

sql_labels_err = "GCP SQL Instances without any Label information" {
    gc_issue["sql_labels"]
}

#
# PR-GCP-0063-TRF
#

default sql_binary_logs = null


gc_attribute_absence["sql_binary_logs"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    not resource.properties.databaseVersion
}

gc_issue["sql_binary_logs"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.databaseVersion), "mysql")
    not resource.properties.settings.backupConfiguration.binaryLogEnabled
}

sql_binary_logs {
    lower(input.resources[_].type) == "google_sql_database_instance"
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
# PR-GCP-0064-TRF
#

default sql_backup = null


gc_attribute_absence["sql_backup"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    not resource.properties.settings.backupConfiguration
}

gc_issue["sql_backup"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    not resource.properties.settings.backupConfiguration.enabled
}

sql_backup {
    lower(input.resources[_].type) == "google_sql_database_instance"
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
# PR-GCP-0066-TRF
#

default sql_ssl = null


gc_attribute_absence["sql_ssl"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    not resource.properties.settings.ip_configuration.requireSsl
}

gc_issue["sql_ssl"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    resource.properties.settings.ip_configuration.requireSsl != true
}

sql_ssl {
    lower(input.resources[_].type) == "google_sql_database_instance"
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

sql_ssl_miss_err = "GCP DB Instance attribute ip_configuration.requireSsl missing in the resource" {
    gc_attribute_absence["sql_ssl"]
}

#
# PR-GCP-0067-TRF
#

default sql_exposed = null


gc_attribute_absence["sql_exposed"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    not resource.properties.settings.ip_configuration.authorized_networks
}

gc_issue["sql_exposed"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    resource.properties.settings.ip_configuration.authorized_networks[_] == "0.0.0.0"
}

gc_issue["sql_exposed"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    resource.properties.settings.ip_configuration.authorized_networks[_] == "0.0.0.0/0"
}

gc_issue["sql_exposed"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    resource.properties.settings.ip_configuration.authorized_networks[_] == "::/0"
}

sql_exposed {
    lower(input.resources[_].type) == "google_sql_database_instance"
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

sql_exposed_miss_err = "GCP DB Instance attribute ip_configuration.authorized_networks missing in the resource" {
    gc_attribute_absence["sql_exposed"]
}
