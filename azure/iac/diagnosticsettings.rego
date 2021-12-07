package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings
# https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/resource-manager-diagnostic-settings
#
# PR-AZR-ARM-MNT-002
#

default log_keyvault = null

azure_attribute_absence ["log_keyvault"] {
    count([c | lower(input.resources[_].type) == "microsoft.keyvault/vaults"; c := 1]) != count([c | lower(input.resources[_].type) == "microsoft.insights/diagnosticsettings"; c := 1])
}

azure_attribute_absence["log_keyvault"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.keyvault/vaults")
}

source_path[{"log_keyvault":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.keyvault/vaults")
    metadata:= {
        "resource_path": [["resources",i,"scope"]]
    }
}

azure_attribute_absence["log_keyvault"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not resource.properties.logs
}

source_path[{"log_keyvault":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.keyvault/vaults"
    not resource.properties.logs
    metadata:= {
        "resource_path": [["resources",i,"properties","logs"]]
    }
}

azure_issue["log_keyvault"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[_]
    log.enabled != true
}

source_path[{"log_keyvault":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[j]
    log.enabled != true
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"enabled"]]
    }
}

log_keyvault {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not azure_attribute_absence["log_keyvault"]
    not azure_issue["log_keyvault"]
}

log_keyvault = false {
	lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    azure_issue["log_keyvault"]
}

log_keyvault = false {
	lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    azure_attribute_absence["log_keyvault"]
}

log_keyvault_err = "Azure Key Vault audit logging is currently not enabled" {
	lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    azure_issue["log_keyvault"]
} else = "Azure Keyvault diagnostic settings attribute 'logs' is missing from the resource" {
	lower(input.resources[_].type) == "microsoft.keyvault/vaults"
	azure_attribute_absence["log_keyvault"]
}

log_keyvault_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Key Vault audit logging should be enabled",
    "Policy Description": "This policy identifies Azure Key Vault instances for which audit logging is disabled. As a best practice, enable audit event logging for Key Vault instances to monitor how and when your key vaults are accessed, and by whom.",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings"
}

#
# PR-AZR-ARM-MNT-003
#
default log_lbs = null

azure_attribute_absence ["log_lbs"] {
    count([c | lower(input.resources[_].type) == "microsoft.network/loadbalancers"; c := 1]) != count([c | lower(input.resources[_].type) == "microsoft.insights/diagnosticsettings"; c := 1])
}

azure_attribute_absence["log_lbs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.network/loadbalancers")
}

source_path[{"log_lbs":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.network/loadbalancers")
    metadata:= {
        "resource_path": [["resources",i,"scope"]]
    }
}

azure_attribute_absence["log_lbs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not resource.properties.logs
}

source_path[{"log_lbs":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not resource.properties.logs
    metadata:= {
        "resource_path": [["resources",i,"properties","logs"]]
    }
}

azure_issue["log_lbs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[_]
    log.enabled != true
}

source_path[{"log_lbs":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[j]
    log.enabled != true
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"enabled"]]
    }
}

log_lbs {
    lower(input.resources[_].type) == "microsoft.network/loadbalancers"
    not azure_attribute_absence["log_lbs"]
    not azure_issue["log_lbs"]
}

log_lbs = false {
	lower(input.resources[_].type) == "microsoft.network/loadbalancers"
    azure_issue["log_lbs"]
}

log_lbs = false {
	lower(input.resources[_].type) == "microsoft.network/loadbalancers"
    azure_attribute_absence["log_lbs"]
}

log_lbs_err = "Azure Load Balancer diagnostics logging is currently not enabled" {
	lower(input.resources[_].type) == "microsoft.network/loadbalancers"
    azure_issue["log_lbs"]
} else = "Azure Load Balancer diagnostic settings attribute 'logs' is missing from the resource" {
	lower(input.resources[_].type) == "microsoft.network/loadbalancers"
	azure_attribute_absence["log_lbs"]
}

log_lbs_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Load Balancer diagnostics logs should be enabled",
    "Policy Description": "Azure Load Balancers provide different types of logsâ€”alert events, health probe, metricsâ€”to help you manage and troubleshoot issues. This policy identifies Azure Load Balancers that have diagnostics logs disabled. As a best practice, enable diagnostic logs to start collecting the data available through these logs.",
    "Resource Type": "microsoft.insights/diagnosticsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings"
}

# PR-AZR-ARM-MNT-004
#
default log_storage_retention = null

azure_attribute_absence["log_storage_retention"] {
    count([c | lower(input.resources[_].type) == "microsoft.insights/diagnosticsettings"; c := 1]) != count([c | lower(input.resources[_].type) == "microsoft.storage/storageaccounts"; c := 1])
}

azure_attribute_absence["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.storage/storageaccounts")
}

source_path[{"log_storage_retention":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.storage/storageaccounts")
    metadata:= {
        "resource_path": [["resources",i,"scope"]]
    }
}

azure_attribute_absence["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[_]
    not log.enabled
}

source_path[{"log_storage_retention":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[j]
    not log.enabled
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"enabled"]]
    }
}

azure_attribute_absence["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[_]
    not log.retentionPolicy.enabled
}

source_path[{"log_storage_retention":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[j]
    not log.retentionPolicy.enabled
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"retentionPolicy","enabled"]]
    }
}

azure_attribute_absence["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[_]
    not log.retentionPolicy.days
}

source_path[{"log_storage_retention":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[j]
    not log.retentionPolicy.days
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"retentionPolicy","days"]]
    }
}

azure_issue["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[_]
    log.enabled != true
}

source_path[{"log_storage_retention":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[j]
    log.enabled != true
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"enabled"]]
    }
}

azure_issue["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[_]
    log.retentionPolicy.enabled != true
}

source_path[{"log_storage_retention":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[j]
    log.retentionPolicy.enabled != true
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"retentionPolicy","enabled"]]
    }
}

azure_issue["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[_]
    to_number(log.retentionPolicy.days) < 90
}

source_path[{"log_storage_retention":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[j]
    to_number(log.retentionPolicy.days) < 90
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"retentionPolicy","days"]]
    }
}

log_storage_retention {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_attribute_absence["log_storage_retention"]
    not azure_issue["log_storage_retention"]
}

log_storage_retention = false {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    azure_issue["log_storage_retention"]
}

log_storage_retention = false {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    azure_attribute_absence["log_storage_retention"]
}

log_storage_retention_err = "Azure Storage Account with Auditing Retention is currently less than 90 days. Its need to be 90 days or more" {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    azure_issue["log_storage_retention"]
} else = "Azure Storage Account diagnostics attribute 'logs' is missing from the resource" {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
	azure_attribute_absence["log_storage_retention"]
}

log_storage_retention_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Storage Account auditing retention should be 90 days or more",
    "Policy Description": "This policy identifies Storage Accounts which have Auditing Retentions less than 90 days. Audit Logs can be used to check for anomalies and gives insight into suspected breaches or misuse of information and access. It is recommended to configure Storage Account Audit Log Retention to be greater than or equal to 90 days.",
    "Resource Type": "microsoft.insights/diagnosticsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings"
}

# PR-AZR-ARM-MNT-005
#
default log_blob = null

azure_attribute_absence ["log_blob"] {
    count([c | lower(input.resources[_].type) == "microsoft.storage/storageaccounts/blobservices"; c := 1]) != count([c | lower(input.resources[_].type) == "microsoft.insights/diagnosticsettings"; c := 1])
}

azure_attribute_absence["log_blob"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.storage/storageaccounts/blobservices")
}

source_path[{"log_blob":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.storage/storageaccounts/blobservices")
    metadata:= {
        "resource_path": [["resources",i,"scope"]]
    }
}

azure_attribute_absence["log_blob"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not resource.properties.logs
}

source_path[{"log_blob":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not resource.properties.logs
    metadata:= {
        "resource_path": [["resources",i,"properties","logs"]]
    }
}

azure_issue["log_blob"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[_]
    log.enabled != true
}

source_path[{"log_blob":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[j]
    log.enabled != true
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"enabled"]]
    }
}

log_blob {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/blobservices"
    not azure_attribute_absence["log_blob"]
    not azure_issue["log_blob"]
}

log_blob = false {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts/blobservices"
    azure_issue["log_blob"]
}

log_blob = false {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts/blobservices"
    azure_attribute_absence["log_blob"]
}

log_blob_err = "Azure storage account blob services diagnostics logging is currently not enabled" {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts/blobservices"
    azure_issue["log_blob"]
} else = "Azure storage account blob services diagnostic settings attribute 'logs' is missing from the resource" {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts/blobservices"
	azure_attribute_absence["log_blob"]
}

log_blob_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure storage account blob services diagnostics logs should be enabled",
    "Policy Description": "torage Logging records details of requests (read, write, and delete operations) against your Azure blobs. The logs include additional information such as:<br>- Timing and server latency.<br>- Success or failure, and HTTP status code.<br>- Authentication details<br><br>This policy identifies Azure storage accounts that do not have logging enabled for blobs. As a best practice, enable logging for read, write, and delete request types on blobs.",
    "Resource Type": "microsoft.insights/diagnosticsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings"
}


# PR-AZR-ARM-MNT-006
#
default log_queue = null

azure_attribute_absence ["log_queue"] {
    count([c | lower(input.resources[_].type) == "microsoft.storage/storageaccounts/queueservices"; c := 1]) != count([c | lower(input.resources[_].type) == "microsoft.insights/diagnosticsettings"; c := 1])
}

azure_attribute_absence["log_queue"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.storage/storageaccounts/queueservices")
}

source_path[{"log_queue":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.storage/storageaccounts/queueservices")
    metadata:= {
        "resource_path": [["resources",i,"scope"]]
    }
}

azure_attribute_absence["log_queue"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not resource.properties.logs
}

source_path[{"log_queue":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not resource.properties.logs
    metadata:= {
        "resource_path": [["resources",i,"properties","logs"]]
    }
}

azure_issue["log_queue"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[_]
    log.enabled != true
}

source_path[{"log_queue":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[j]
    log.enabled != true
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"enabled"]]
    }
}

log_queue {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/queueservices"
    not azure_attribute_absence["log_queue"]
    not azure_issue["log_queue"]
}

log_queue = false {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts/queueservices"
    azure_issue["log_queue"]
}

log_queue = false {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts/queueservices"
    azure_attribute_absence["log_queue"]
}

log_queue_err = "Azure storage account queue services diagnostics logging is currently not enabled" {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts/queueservices"
    azure_issue["log_queue"]
} else = "Azure storage account queue services diagnostic settings attribute 'logs' is missing from the resource" {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts/queueservices"
	azure_attribute_absence["log_queue"]
}

log_queue_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure storage account queue services diagnostics logs should be enabled",
    "Policy Description": "Storage Logging records details of requests (read, write, and delete operations) against your Azure queues. The logs include additional information such as:<br>- Timing and server latency.<br>- Success or failure, and HTTP status code.<br>- Authentication details<br><br>This policy identifies Azure storage accounts that do not have logging enabled for queues. As a best practice, enable logging for read, write, and delete request types on queues.",
    "Resource Type": "microsoft.insights/diagnosticsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings"
}


# PR-AZR-ARM-MNT-007
#
default log_table = null

azure_attribute_absence ["log_table"] {
    count([c | lower(input.resources[_].type) == "microsoft.storage/storageaccounts/tableservices"; c := 1]) != count([c | lower(input.resources[_].type) == "microsoft.insights/diagnosticsettings"; c := 1])
}

azure_attribute_absence["log_table"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.storage/storageaccounts/tableservices")
}

source_path[{"log_table":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.storage/storageaccounts/tableservices")
    metadata:= {
        "resource_path": [["resources",i,"scope"]]
    }
}

azure_attribute_absence["log_table"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not resource.properties.logs
}

source_path[{"log_table":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not resource.properties.logs
    metadata:= {
        "resource_path": [["resources",i,"properties","logs"]]
    }
}

azure_issue["log_table"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[_]
    log.enabled != true
}

source_path[{"log_table":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    log := resource.properties.logs[j]
    log.enabled != true
    metadata:= {
        "resource_path": [["resources",i,"properties","logs",j,"enabled"]]
    }
}

log_table {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/tableservices"
    not azure_attribute_absence["log_table"]
    not azure_issue["log_table"]
}

log_table = false {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts/tableservices"
    azure_issue["log_table"]
}

log_table = false {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts/tableservices"
    azure_attribute_absence["log_table"]
}

log_table_err = "Azure storage account table services diagnostics logging is currently not enabled" {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts/tableservices"
    azure_issue["log_table"]
} else = "Azure storage account table services diagnostic settings attribute 'logs' is missing from the resource" {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts/tableservices"
	azure_attribute_absence["log_table"]
}

log_table_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-007",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure storage account table services diagnostics logs should be enabled",
    "Policy Description": "Storage Logging records details of requests (read, write, and delete operations) against your Azure queues. The logs include additional information such as:<br>- Timing and server latency.<br>- Success or failure, and HTTP status code.<br>- Authentication details<br><br>This policy identifies Azure storage accounts that do not have logging enabled for tables. As a best practice, enable logging for read, write, and delete request types on tables.",
    "Resource Type": "microsoft.insights/diagnosticsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings"
}
