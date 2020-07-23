package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings

#
# Azure Key Vault audit logging is disabled (226)
#

default log_keyvault = null

azure_attribute_absence["log_keyvault"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults/providers/diagnosticsettings"
    not resource.properties.logs
}

azure_issue["log_keyvault"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults/providers/diagnosticsettings"
    logs := resource.properties.logs[_]
    lower(logs.category) == "auditevent"
    logs.enabled != true
}

log_keyvault {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults/providers/diagnosticsettings"
    not azure_issue["log_keyvault"]
    not azure_attribute_absence["log_keyvault"]
}

log_keyvault = false {
    azure_issue["log_keyvault"]
}

log_keyvault = false {
    azure_attribute_absence["log_keyvault"]
}

log_keyvault_err = "Azure Key Vault audit logging is disabled" {
    azure_issue["log_keyvault"]
}

log_keyvault_miss_err = "Diagnostics attribute logs missing in the resource" {
    azure_attribute_absence["log_keyvault"]
}

















#
# Azure Load Balancer diagnostics logs are disabled (228)
#

default log_lbs = null

azure_attribute_absence["log_lbs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/loadbalancers/providers/diagnosticsettings"
    not resource.properties.logs
}

azure_issue["log_lbs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/loadbalancers/providers/diagnosticsettings"
    count(resource.properties.logs) == 0
}

azure_issue["log_lbs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/loadbalancers/providers/diagnosticsettings"
    resource.properties.logs[_].enabled == false
}

log_lbs {
    lower(input.resources[_].type) == "microsoft.network/loadbalancers/providers/diagnosticsettings"
    not azure_issue["log_lbs"]
    not azure_attribute_absence["log_lbs"]
}

log_lbs = false {
    azure_issue["log_lbs"]
}

log_lbs = false {
    azure_attribute_absence["log_lbs"]
}

log_lbs_err = "Azure storage account logging for queues is disabled" {
    azure_issue["log_lbs"]
}

log_lbs_miss_err = "Azure Load Balancer diagnostics logs are disabled" {
    azure_attribute_absence["log_lbs"]
}

#
# Azure Storage Account with Auditing Retention less than 90 days (272)
#

default log_storage_retention = null

azure_attribute_absence["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    not resource.properties.logs
}

azure_issue["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    logs := resource.properties.logs[_]
    lower(logs.category) == "auditevent"
    logs.enabled != true
}

azure_issue["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    logs := resource.properties.logs[_]
    lower(logs.category) == "auditevent"
    logs.retentionPolicy.enabled != true
}

azure_issue["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    logs := resource.properties.logs[_]
    lower(logs.category) == "auditevent"
    count(logs.retentionPolicy) < 2
}

azure_issue["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    logs := resource.properties.logs[_]
    lower(logs.category) == "auditevent"
    to_number(logs.retentionPolicy.days) < 90
}

log_storage_retention {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    not azure_issue["log_storage_retention"]
    not azure_attribute_absence["log_storage_retention"]
}

log_storage_retention = false {
    azure_issue["log_storage_retention"]
}

log_storage_retention = false {
    azure_attribute_absence["log_storage_retention"]
}

log_storage_retention_err = "Azure Storage Account with Auditing Retention less than 90 days" {
    azure_issue["log_storage_retention"]
}

log_storage_retention_miss_err = "Diagnostics attribute logs missing in the resource" {
    azure_attribute_absence["log_storage_retention"]
}

#
# Azure storage account logging for blobs is disabled (278)
#

default log_blob = null

azure_attribute_absence["log_blob"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings"
    not resource.properties.logs
}

azure_issue["log_blob"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings"
    count(resource.properties.logs) == 0
}

azure_issue["log_blob"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings"
    resource.properties.logs[_].enabled == false
}

log_blob {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings"
    not azure_issue["log_blob"]
    not azure_attribute_absence["log_blob"]
}

log_blob = false {
    azure_issue["log_blob"]
}

log_blob = false {
    azure_attribute_absence["log_blob"]
}

log_blob_err = "Azure storage account logging for blobs is disabled" {
    azure_issue["log_blob"]
}

log_blob_miss_err = "Diagnostics attribute logs missing in the resource" {
    azure_attribute_absence["log_blob"]
}

#
# Azure storage account logging for queues is disabled (279)
# Azure storage account logging for queues is disabled TJX (280)
#

default log_queue = null

azure_attribute_absence["log_queue"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings"
    not resource.properties.logs
}

azure_issue["log_queue"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings"
    count(resource.properties.logs) == 0
}

azure_issue["log_queue"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings"
    resource.properties.logs[_].enabled == false
}

log_queue {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings"
    not azure_issue["log_queue"]
    not azure_attribute_absence["log_queue"]
}

log_queue = false {
    azure_issue["log_queue"]
}

log_queue = false {
    azure_attribute_absence["log_queue"]
}

log_queue_err = "Azure storage account logging for queues is disabled" {
    azure_issue["log_queue"]
}

log_queue_miss_err = "Diagnostics attribute logs missing in the resource" {
    azure_attribute_absence["log_queue"]
}

#
# Azure storage account logging for tables is disabled (281)
# Azure storage account logging for tables is disabled TJX (282)
#

default log_table = null

azure_attribute_absence["log_table"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings"
    not resource.properties.logs
}

azure_issue["log_table"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings"
    count(resource.properties.logs) == 0
}

azure_issue["log_table"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings"
    resource.properties.logs[_].enabled == false
}

log_table {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings"
    not azure_issue["log_table"]
    not azure_attribute_absence["log_table"]
}

log_table = false {
    azure_issue["log_table"]
}

log_table = false {
    azure_attribute_absence["log_table"]
}

log_table_err = "Azure storage account logging for tables is disabled" {
    azure_issue["log_table"]
}

log_table_miss_err = "Diagnostics attribute logs missing in the resource" {
    azure_attribute_absence["log_table"]
}
