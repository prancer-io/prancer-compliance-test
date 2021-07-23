package rule

# https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances

#
# PR-GCP-0062-TRF
#

default sql_labels = null

gc_issue["sql_labels"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    resource.properties.settings != null
    not resource.properties.settings[_].userLabels
}

gc_issue["sql_labels"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    resource.properties.settings != null
    count(resource.properties.settings[_].userLabels) == 0
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

sql_labels_metadata := {
    "Policy Code": "PR-GCP-0062-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP SQL Instances without any Label information",
    "Policy Description": "This policy identifies the SQL DB instance which does not have any Labels. Labels can be used for easy identification and searches.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
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
    settings := resource.properties.settings[_]
    backup_configuration := settings.backup_configuration[_]
    not backup_configuration.binary_log_enabled
}

sql_binary_logs {
    lower(input.resources[_].type) == "google_sql_database_instance"
    not gc_issue["sql_binary_logs"]
    not gc_attribute_absence["sql_binary_logs"]
}

sql_binary_logs = false {
    gc_issue["sql_binary_logs"]
} else = false {
    gc_attribute_absence["sql_binary_logs"]
}

sql_binary_logs_err = "SQL DB Instance backup Binary logs configuration is not enabled" {
    gc_issue["sql_binary_logs"]
} else = "GCP DB Instance attribute databaseVersion missing in the resource" {
    gc_attribute_absence["sql_binary_logs"]
}

sql_binary_logs_metadata := {
    "Policy Code": "PR-GCP-0063-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Storage bucket encrypted using default KMS key instead of a customer-managed key",
    "Policy Description": "This policy identifies Storage buckets that are encrypted with the default Google-managed keys. As a best practice, use Customer-managed key to encrypt the data in your storage bucket and ensure full control over your data.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}

#
# PR-GCP-0064-TRF
#

default sql_backup = null

gc_attribute_absence["sql_backup"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    not resource.properties.settings
}

gc_attribute_absence["sql_backup"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    count(resource.properties.settings) = 0
}

gc_attribute_absence["sql_backup"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    settings := resource.properties.settings[_]
    not settings.backup_configuration
}

gc_issue["sql_backup"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    settings := resource.properties.settings[_]
    backup_configuration := settings.backup_configuration[_]
    not backup_configuration.enabled
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
} else = "GCP DB Instance attribute backupConfiguration missing in the resource" {
    gc_attribute_absence["sql_backup"]
}

sql_backup_metadata := {
    "Policy Code": "PR-GCP-0064-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Storage buckets are publicly accessible to all authenticated users",
    "Policy Description": "This policy identifies the buckets which are publicly accessible to all authenticated users. Enabling public access to Storage Buckets enables anybody with a web association to access sensitive information that is critical to business. Access over a whole bucket is controlled by IAM. Access to individual objects within the bucket is controlled by its ACLs.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}

#
# PR-GCP-0066-TRF
#

default sql_ssl = null

gc_attribute_absence["sql_ssl"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    not resource.properties.settings
}

gc_attribute_absence["sql_ssl"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    count(resource.properties.settings)
}

gc_attribute_absence["sql_ssl"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    settings := resource.properties.settings[_]
    ip_configuration := settings.ip_configuration[_]
    not ip_configuration.require_ssl
}

gc_issue["sql_ssl"] {
    resource := input.resources[_]
    lower(resource.type) == "google_sql_database_instance"
    settings := resource.properties.settings[_]
    ip_configuration := settings.ip_configuration[_]
    ip_configuration.require_ssl != true
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
} else = "GCP DB Instance attribute ip_configuration.requireSsl missing in the resource" {
    gc_attribute_absence["sql_ssl"]
}

sql_ssl_metadata := {
    "Policy Code": "PR-GCP-0066-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Storage log buckets have object versioning disabled",
    "Policy Description": "This policy identifies Storage log buckets which have object versioning disabled. Enabling object versioning on storage log buckets will protect your cloud storage data from being overwritten or accidentally deleted. It is recommended to enable object versioning feature on all storage buckets where sinks are configured.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
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

sql_exposed_metadata := {
    "Policy Code": "PR-GCP-0067-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP User managed service account keys are not rotated for 90 days",
    "Policy Description": "This policy identifies user-managed service account keys which are not rotated from last 90 days or more. Rotating Service Account keys will reduce the window of opportunity for an access key that is associated with a compromised or terminated account to be used. Service Account keys should be rotated to ensure that data cannot be accessed with an old key which might have been lost, cracked, or stolen. It is recommended that all user-managed service account keys are regularly rotated.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}
