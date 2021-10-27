package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings
# https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/resource-manager-diagnostic-settings
#
# PR-AZR-ARM-MNT-002
#

default log_keyvault = null

azure_attribute_absence["log_keyvault"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults/providers/diagnosticsettings"
    not resource.properties.logs
}

source_path[{"log_keyvault":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.keyvault/vaults/providers/diagnosticsettings"
    not resource.properties.logs
    metadata:= {
        "resource_path": [["resources",i,"properties","logs"]]
    }
}

azure_issue["log_keyvault"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults/providers/diagnosticsettings"
    log := resource.properties.logs[_]
    lower(log.category) == "auditevent"
    log.enabled == false
}

source_path[{"log_keyvault":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.keyvault/vaults/providers/diagnosticsettings"
    log := resource.properties.logs[j]
    lower(log.category) == "auditevent"
    log.enabled == false
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"category"]]
    }
}

log_keyvault {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults/providers/diagnosticsettings"
    not azure_attribute_absence["log_keyvault"]
    not azure_issue["log_keyvault"]
}

log_keyvault = false {
    azure_issue["log_keyvault"]
}

log_keyvault = false {
    azure_attribute_absence["log_keyvault"]
}

log_keyvault_err = "Azure Key Vault audit logging is currently not enabled" {
    azure_issue["log_keyvault"]
}

log_keyvault_miss_err = "Azure Keyvault diagnostic settings attribute 'logs' is missing from the resource" {
    azure_attribute_absence["log_keyvault"]
}

log_keyvault_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Key Vault audit logging should be enabled",
    "Policy Description": "This policy identifies Azure Key Vault instances for which audit logging is disabled. As a best practice, enable audit event logging for Key Vault instances to monitor how and when your key vaults are accessed, and by whom.",
    "Resource Type": "microsoft.keyvault/vaults/providers/diagnosticsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings"
}

#
# PR-AZR-ARM-MNT-003
#

default log_lbs = null

azure_attribute_absence["log_lbs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/loadbalancers/providers/diagnosticsettings"
    not resource.properties.logs
}

source_path[{"log_lbs":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.network/loadbalancers/providers/diagnosticsettings"
    not resource.properties.logs
    metadata:= {
        "resource_path": [["resources",i,"properties","logs"]]
    }
}


azure_issue["log_lbs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/loadbalancers/providers/diagnosticsettings"
    count(resource.properties.logs) == 0
}

source_path[{"log_lbs":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.network/loadbalancers/providers/diagnosticsettings"
    count(resource.properties.logs) == 0
    metadata:= {
        "resource_path": [["resources",i,"properties","logs"]]
    }
}

azure_issue["log_lbs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/loadbalancers/providers/diagnosticsettings"
    log := resource.properties.logs[_]
    lower(log.enabled) == "false"
}

source_path[{"log_lbs":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.network/loadbalancers/providers/diagnosticsettings"
    log := resource.properties.logs[j]
    lower(log.enabled) == "false"
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"enabled"]]
    }
}

log_lbs {
    lower(input.resources[_].type) == "microsoft.network/loadbalancers/providers/diagnosticsettings"
    not azure_attribute_absence["log_lbs"]
    not azure_issue["log_lbs"]
}

log_lbs = false {
    azure_issue["log_lbs"]
}

log_lbs = false {
    azure_attribute_absence["log_lbs"]
}

log_lbs_err = "Azure Load Balancer diagnostics logging is currently not enabled" {
    azure_issue["log_lbs"]
}

log_lbs_miss_err = "Azure Load Balancer diagnostic settings attribute 'logs' is missing from the resource" {
    azure_attribute_absence["log_lbs"]
}

log_lbs_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Load Balancer diagnostics logs should be enabled",
    "Policy Description": "Azure Load Balancers provide different types of logsâ€”alert events, health probe, metricsâ€”to help you manage and troubleshoot issues. This policy identifies Azure Load Balancers that have diagnostics logs disabled. As a best practice, enable diagnostic logs to start collecting the data available through these logs.",
    "Resource Type": "microsoft.network/loadbalancers/providers/diagnosticsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings"
}

#
# PR-AZR-ARM-MNT-004
#

default log_storage_retention = null

azure_attribute_absence["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    not resource.properties.logs
}

source_path[{"log_storage_retention":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    not resource.properties.logs
    metadata:= {
        "resource_path": [["resources",i,"properties","logs"]]
    }
}

azure_attribute_absence["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    log := resource.properties.logs[_]
    not log.retentionPolicy.enabled
}

source_path[{"log_storage_retention":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    log := resource.properties.logs[j]
    not log.retentionPolicy.enabled
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"retentionPolicy","enabled"]]
    }
}

azure_issue["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    log := resource.properties.logs[_]
    lower(log.category) == "auditevent"
    log.enabled != true
}

source_path[{"log_storage_retention":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    log := resource.properties.logs[j]
    lower(log.category) == "auditevent"
    log.enabled != true
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"category"]]
    }
}

azure_issue["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    log := resource.properties.logs[_]
    lower(log.category) == "auditevent"
    log.retentionPolicy.enabled != true
}

source_path[{"log_storage_retention":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    log := resource.properties.logs[j]
    lower(log.category) == "auditevent"
    log.retentionPolicy.enabled != true
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"category"]]
    }
}

#azure_issue["log_storage_retention"] {
#    resource := input.resources[_]
#    lower(resource.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
#    logs := resource.properties.logs[_]
#    lower(logs.category) == "auditevent"
#    count(logs.retentionPolicy) < 2
#}

azure_issue["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    log := resource.properties.logs[_]
    lower(log.category) == "auditevent"
    to_number(log.retentionPolicy.days) < 90
}

source_path[{"log_storage_retention":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    log := resource.properties.logs[j]
    lower(log.category) == "auditevent"
    to_number(log.retentionPolicy.days) < 90
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"retentionPolicy","days"]]
    }
}

log_storage_retention {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/providers/diagnosticsettings"
    not azure_attribute_absence["log_storage_retention"]
    not azure_issue["log_storage_retention"]
}

log_storage_retention = false {
    azure_issue["log_storage_retention"]
}

log_storage_retention = false {
    azure_attribute_absence["log_storage_retention"]
}

log_storage_retention_err = "Azure Storage Account with Auditing Retention is currently less than 90 days. Its need to be 90 days or more" {
    azure_issue["log_storage_retention"]
}

log_storage_retention_miss_err = "Azure Storage Account diagnostics attribute 'logs' is missing from the resource" {
    azure_attribute_absence["log_storage_retention"]
}

log_storage_retention_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Storage Account auditing retention should be 90 days or more",
    "Policy Description": "This policy identifies Storage Accounts which have Auditing Retentions less than 90 days. Audit Logs can be used to check for anomalies and gives insight into suspected breaches or misuse of information and access. It is recommended to configure Storage Account Audit Log Retention to be greater than or equal to 90 days.",
    "Resource Type": "microsoft.storage/storageaccounts/providers/diagnosticsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings"
}

#
# PR-AZR-ARM-MNT-005
#

default log_blob = null

azure_attribute_absence["log_blob"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings"
    not resource.properties.logs
}

source_path[{"log_blob":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings"
    not resource.properties.logs
    metadata:= {
        "resource_path": [["resources",i,"properties","logs"]]
    }
}

azure_issue["log_blob"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings"
    count(resource.properties.logs) == 0
}

source_path[{"log_blob":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings"
    count(resource.properties.logs) == 0
    metadata:= {
        "resource_path": [["resources",i,"properties","logs"]]
    }
}

azure_issue["log_blob"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings"
    log := resource.properties.logs[_]
    log.enabled == false
}

source_path[{"log_blob":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings"
    log := resource.properties.logs[j]
    log.enabled == false
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"enabled"]]
    }
}

log_blob {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings"
    not azure_attribute_absence["log_blob"]
    not azure_issue["log_blob"]
    
}

log_blob = false {
    azure_issue["log_blob"]
}

log_blob = false {
    azure_attribute_absence["log_blob"]
}

log_blob_err = "Azure storage account blob services diagnostic logs is currently not enabled" {
    azure_issue["log_blob"]
}

log_blob_miss_err = "Azure storage account blob services diagnostic logs attribute 'logs' is missing from the resource" {
    azure_attribute_absence["log_blob"]
}

log_blob_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure storage account blob services diagnostic logs should be enabled",
    "Policy Description": "Storage Logging records details of requests (read, write, and delete operations) against your Azure blobs. The logs include additional information such as:<br>- Timing and server latency.<br>- Success or failure, and HTTP status code.<br>- Authentication details<br><br>This policy identifies Azure storage accounts that do not have logging enabled for blobs. As a best practice, enable logging for read, write, and delete request types on blobs.",
    "Resource Type": "microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings"
}

#
# PR-AZR-ARM-MNT-006
#

default log_queue = null

azure_attribute_absence["log_queue"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings"
    not resource.properties.logs
}

source_path[{"log_queue":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings"
    not resource.properties.logs
    metadata:= {
        "resource_path": [["resources",i,"properties","logs"]]
    }
}

azure_issue["log_queue"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings"
    count(resource.properties.logs) == 0
}

source_path[{"log_queue":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings"
    count(resource.properties.logs) == 0
    metadata:= {
        "resource_path": [["resources",i,"properties","logs"]]
    }
}

azure_issue["log_queue"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings"
    log:= resource.properties.logs[_]
    log.enabled == false
}

source_path[{"log_queue":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings"
    log:= resource.properties.logs[j]
    log.enabled == false
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"enabled"]]
    }
}

log_queue {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings"
    not azure_attribute_absence["log_queue"]
    not azure_issue["log_queue"]
}

log_queue = false {
    azure_issue["log_queue"]
}

log_queue = false {
    azure_attribute_absence["log_queue"]
}

log_queue_err = "Azure storage account queue services diagnostic logs is currently not enabled" {
    azure_issue["log_queue"]
}

log_queue_miss_err = "Azure storage account queue services diagnostic logs attribute 'logs' is missing from the resource" {
    azure_attribute_absence["log_queue"]
}

log_queue_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure storage account queue services diagnostic logs should be enabled",
    "Policy Description": "Storage Logging records details of requests (read, write, and delete operations) against your Azure queues. The logs include additional information such as:<br>- Timing and server latency.<br>- Success or failure, and HTTP status code.<br>- Authentication details<br><br>This policy identifies Azure storage accounts that do not have logging enabled for queues. As a best practice, enable logging for read, write, and delete request types on queues.",
    "Resource Type": "microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings"
}

#
# PR-AZR-ARM-MNT-007
#

default log_table = null

azure_attribute_absence["log_table"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings"
    not resource.properties.logs
}

source_path[{"log_table":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings"
    not resource.properties.logs
    metadata:= {
        "resource_path": [["resources",i,"properties","logs"]]
    }
}

azure_issue["log_table"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings"
    count(resource.properties.logs) == 0
}

source_path[{"log_table":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings"
    count(resource.properties.logs) == 0
    metadata:= {
        "resource_path": [["resources",i,"properties","logs"]]
    }
}

azure_issue["log_table"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings"
    log:= resource.properties.logs[_]
    log.enabled == false
}

source_path[{"log_table":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings"
    log:= resource.properties.logs[j]
    log.enabled == false
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"enabled"]]
    }
}

log_table {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings"
    not azure_attribute_absence["log_table"]
    not azure_issue["log_table"]
}

log_table = false {
    azure_issue["log_table"]
}

log_table = false {
    azure_attribute_absence["log_table"]
}

log_table_err = "Azure storage account table services diagnostic logs is currently not enabled" {
    azure_issue["log_table"]
}

log_table_miss_err = "Azure storage account table services diagnostic logs attribute 'logs' is missing from the resource" {
    azure_attribute_absence["log_table"]
}

log_table_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-007",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure storage account table services diagnostic logs should be enabled",
    "Policy Description": "Storage Logging records details of requests (read, write, and delete operations) against your Azure queues. The logs include additional information such as:<br>- Timing and server latency.<br>- Success or failure, and HTTP status code.<br>- Authentication details<br><br>This policy identifies Azure storage accounts that do not have logging enabled for tables. As a best practice, enable logging for read, write, and delete request types on tables.",
    "Resource Type": "microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings"
}
