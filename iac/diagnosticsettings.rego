package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings

#
# Azure Key Vault audit logging is disabled (226)
#

default log_keyvault = null

log_keyvault {
    lower(input.type) == "microsoft.keyvault/vaults/providers/diagnosticsettings"
    logs := input.properties.logs[_]
    logs.category == "AuditEvent"
    logs.enabled == true
}

log_keyvault = false {
    lower(input.type) == "microsoft.keyvault/vaults/providers/diagnosticsettings"
    logs := input.properties.logs[_]
    logs.category == "AuditEvent"
    logs.enabled == false
}

log_keyvault_err = "Azure Key Vault audit logging is disabled" {
    log_keyvault == false
}

#
# Azure Load Balancer diagnostics logs are disabled (228)
#

default log_lbs = null

log_lbs {
    lower(input.type) == "microsoft.network/loadbalancers/providers/diagnosticsettings"
    all([c | c := input.properties.logs[_].enabled])
}

log_lbs = false {
    lower(input.type) == "microsoft.network/loadbalancers/providers/diagnosticsettings"
    count(input.properties.logs) == 0
}

log_lbs = false {
    lower(input.type) == "microsoft.network/loadbalancers/providers/diagnosticsettings"
    input.properties.logs[_].enabled == false
}

log_lbs_err = "Azure Load Balancer diagnostics logs are disabled" {
    log_lbs == false
}

#
# Azure Storage Account with Auditing Retention less than 90 days (272)
#

default log_storage_retention = null

log_storage_retention {
    lower(input.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    logs := input.properties.logs[_]
    logs.category == "AuditEvent"
    logs.enabled == true
    logs.retentionPolicy.enabled == true
    logs.retentionPolicy.days >= 90
}

log_storage_retention = false {
    lower(input.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    logs := input.properties.logs[_]
    logs.category == "AuditEvent"
    logs.enabled == false
}

log_storage_retention = false {
    lower(input.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    logs := input.properties.logs[_]
    logs.category == "AuditEvent"
    logs.retentionPolicy.enabled == false
}

log_storage_retention = false {
    lower(input.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    logs := input.properties.logs[_]
    logs.category == "AuditEvent"
    count(logs.retentionPolicy) < 2
}

log_storage_retention = false {
    lower(input.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    logs := input.properties.logs[_]
    logs.category == "AuditEvent"
    logs.retentionPolicy.days < 90
}

log_storage_retention_err = "Azure Storage Account with Auditing Retention less than 90 days" {
    log_storage_retention == false
}

#
# Azure storage account logging for blobs is disabled (278)
#

default log_blob = null

log_blob {
    lower(input.type) == "microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings"
    count(input.properties.logs) > 0
    all([c | c := input.properties.logs[_].enabled])
}

log_blob = false {
    lower(input.type) == "microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings"
    count(input.properties.logs) == 0
}

log_blob = false {
    lower(input.type) == "microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings"
    input.properties.logs[_].enabled == false
}

log_blob_err = "Azure storage account logging for blobs is disabled" {
    log_blob == false
}

#
# Azure storage account logging for queues is disabled (279)
# Azure storage account logging for queues is disabled TJX (280)
#

default log_queue = null

log_queue {
    lower(input.type) == "microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings"
    count(input.properties.logs) > 0
    all([c | c := input.properties.logs[_].enabled])
}

log_queue = false {
    lower(input.type) == "microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings"
    count(input.properties.logs) == 0
}

log_queue = false {
    lower(input.type) == "microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings"
    input.properties.logs[_].enabled == false
}

log_queue_err = "Azure storage account logging for queues is disabled" {
    log_queue == false
}

#
# Azure storage account logging for tables is disabled (281)
# Azure storage account logging for tables is disabled TJX (282)
#

default log_table = null

log_table {
    lower(input.type) == "microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings"
    count(input.properties.logs) > 0
    all([c | c := input.properties.logs[_].enabled])
}

log_table = false {
    lower(input.type) == "microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings"
    count(input.properties.logs) == 0
}

log_table = false {
    lower(input.type) == "microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings"
    input.properties.logs[_].enabled == false
}

log_table_err = "Azure storage account logging for tables is disabled" {
    log_table == false
}
