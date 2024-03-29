package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings
# https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/resource-manager-diagnostic-settings
#
# PR-AZR-ARM-MNT-002
#

default log_keyvault = null

azure_attribute_absence ["log_keyvault"] {
    count([c | lower(input.resources[_].type) == "microsoft.insights/diagnosticsettings"; c := 1]) == 0
}

azure_attribute_absence["log_keyvault"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.keyvault/vaults")
}

azure_attribute_absence["log_keyvault"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not resource.properties.logs
}

log_keyvault {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not azure_attribute_absence["log_keyvault"]
}

log_keyvault = false {
	lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    azure_attribute_absence["log_keyvault"]
}

log_keyvault_err = "Azure Key Vault diagnostics logging is currently not enabled" {
	lower(input.resources[_].type) == "microsoft.keyvault/vaults"
	azure_attribute_absence["log_keyvault"]
}

log_keyvault_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Key Vault diagnostics logs should be enabled",
    "Policy Description": "Azure Key Vault provide different types of logs alert events, health probe, metrics to help you manage and troubleshoot issues. This policy identifies Azure Key Vault that have diagnostics logs disabled. As a best practice, enable diagnostic logs to start collecting the data available through these logs.",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings"
}

#
# PR-AZR-ARM-MNT-003
#
default log_lbs = null

azure_attribute_absence ["log_lbs"] {
    count([c | lower(input.resources[_].type) == "microsoft.insights/diagnosticsettings"; c := 1]) == 0
}

azure_attribute_absence["log_lbs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.network/loadbalancers")
}

azure_attribute_absence["log_lbs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not resource.properties.logs
}

log_lbs {
    lower(input.resources[_].type) == "microsoft.network/loadbalancers"
    not azure_attribute_absence["log_lbs"]
}

log_lbs = false {
	lower(input.resources[_].type) == "microsoft.network/loadbalancers"
    azure_attribute_absence["log_lbs"]
}

log_lbs_err = "Azure Load Balancer diagnostics logging is currently not enabled" {
	lower(input.resources[_].type) == "microsoft.network/loadbalancers"
    azure_attribute_absence["log_lbs"]
}

log_lbs_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Load Balancer diagnostics logs should be enabled",
    "Policy Description": "Azure Load Balancers provide different types of logs alert events, health probe, metrics to help you manage and troubleshoot issues. This policy identifies Azure Load Balancers that have diagnostics logs disabled. As a best practice, enable diagnostic logs to start collecting the data available through these logs.",
    "Resource Type": "microsoft.insights/diagnosticsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings"
}

# PR-AZR-ARM-MNT-004
#
default log_storage_retention = null

azure_attribute_absence["log_storage_retention"] {
    count([c | lower(input.resources[_].type) == "microsoft.insights/diagnosticsettings"; c := 1]) == 0
}

azure_attribute_absence["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.storage/storageaccounts")
}

azure_attribute_absence["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not resource.properties.logs
}

log_storage_retention {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_attribute_absence["log_storage_retention"]
}

log_storage_retention = false {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    azure_attribute_absence["log_storage_retention"]
}

log_storage_retention_err = "Azure Storage Account diagnostics logging is currently not enabled" {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    azure_attribute_absence["log_storage_retention"]
}

log_storage_retention_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Storage Account diagnostic logs should be enabled",
    "Policy Description": "Azure Storage Account provide different types of logs alert events, health probe, metrics to help you manage and troubleshoot issues. This policy identifies Azure Storage Account that have diagnostics logs disabled. As a best practice, enable diagnostic logs to start collecting the data available through these logs.",
    "Resource Type": "microsoft.insights/diagnosticsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings"
}

# PR-AZR-ARM-MNT-005
#
default log_blob = null

azure_attribute_absence ["log_blob"] {
    count([c | lower(input.resources[_].type) == "microsoft.insights/diagnosticsettings"; c := 1]) == 0
}

azure_attribute_absence["log_blob"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.storage/storageaccounts/blobservices")
}

azure_attribute_absence["log_blob"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not resource.properties.logs
}

log_blob {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/blobservices"
    not azure_attribute_absence["log_blob"]
}

log_blob = false {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts/blobservices"
    azure_attribute_absence["log_blob"]
}

log_blob_err = "Azure storage account blob services diagnostics logging is currently not enabled" {
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
    count([c | lower(input.resources[_].type) == "microsoft.insights/diagnosticsettings"; c := 1]) == 0
}

azure_attribute_absence["log_queue"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.storage/storageaccounts/queueservices")
}

azure_attribute_absence["log_queue"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not resource.properties.logs
}

log_queue {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/queueservices"
    not azure_attribute_absence["log_queue"]
}

log_queue = false {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts/queueservices"
    azure_attribute_absence["log_queue"]
}

log_queue_err = "Azure storage account queue services diagnostics logging is currently not enabled" {
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
    count([c | lower(input.resources[_].type) == "microsoft.insights/diagnosticsettings"; c := 1]) == 0
}

azure_attribute_absence["log_table"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.storage/storageaccounts/tableservices")
}

azure_attribute_absence["log_table"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not resource.properties.logs
}

log_table {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/tableservices"
    not azure_attribute_absence["log_table"]
}

log_table = false {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts/tableservices"
    azure_attribute_absence["log_table"]
}

log_table_err = "Azure storage account table services diagnostics logging is currently not enabled" {
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

#
# PR-AZR-ARM-MNT-012
#

default log_redis_cache = null

azure_attribute_absence ["log_redis_cache"] {
    count([c | lower(input.resources[_].type) == "microsoft.insights/diagnosticsettings"; c := 1]) == 0
}

azure_attribute_absence["log_redis_cache"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.cache/redis")
}

azure_attribute_absence["log_redis_cache"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not resource.properties.logs
}

log_redis_cache {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    not azure_attribute_absence["log_redis_cache"]
}

log_redis_cache = false {
	lower(input.resources[_].type) == "microsoft.cache/redis"
    azure_attribute_absence["log_redis_cache"]
}

log_redis_cache_err = "Redis Cache diagnostics logging is currently not enabled" {
	lower(input.resources[_].type) == "microsoft.cache/redis"
	azure_attribute_absence["log_redis_cache"]
}

log_redis_cache_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-012",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Redis Cache diagnostic logs should be enabled",
    "Policy Description": "Diagnostic settings for redis cache used to stream resource logs to a Log Analytics workspace. this policy will identify any redis cache which has this diagnostic settings missing or misconfigured.",
    "Resource Type": "microsoft.cache/redis",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings"
}


#
# PR-AZR-ARM-MNT-013
#

default diagonstic_log_azure_traffic_manager = null

azure_attribute_absence ["diagonstic_log_azure_traffic_manager"] {
    count([c | lower(input.resources[_].type) == "microsoft.insights/diagnosticsettings"; c := 1]) == 0
}

azure_attribute_absence["diagonstic_log_azure_traffic_manager"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.network/trafficmanagerprofiles")
}

azure_attribute_absence["diagonstic_log_azure_traffic_manager"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not resource.properties.logs
}

diagonstic_log_azure_traffic_manager {
    lower(input.resources[_].type) == "microsoft.network/trafficmanagerprofiles"
    not azure_attribute_absence["diagonstic_log_azure_traffic_manager"]
}

diagonstic_log_azure_traffic_manager = false {
	lower(input.resources[_].type) == "microsoft.network/trafficmanagerprofiles"
    azure_attribute_absence["diagonstic_log_azure_traffic_manager"]
}

diagonstic_log_azure_traffic_manager_err = "Azure Traffic Manager diagnostics logging is currently not enabled" {
	lower(input.resources[_].type) == "microsoft.network/trafficmanagerprofiles"
	azure_attribute_absence["diagonstic_log_azure_traffic_manager"]
}

diagonstic_log_azure_traffic_manager_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-013",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Traffic Manager diagnostic logs should be enabled",
    "Policy Description": "Diagnostic settings for Azure Traffic Manager used to stream resource logs to a Log Analytics workspace. this policy will identify any Azure Traffic Manager which has this diagnostic settings missing or misconfigured.",
    "Resource Type": "Microsoft.Network/trafficManagerProfiles",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.network/trafficmanagerprofiles?pivots=deployment-language-arm-template"
}


#
# PR-AZR-ARM-MNT-025
#

default diagonstic_log_azure_eventhub_namespaces = null

azure_attribute_absence ["diagonstic_log_azure_eventhub_namespaces"] {
    count([c | lower(input.resources[_].type) == "microsoft.insights/diagnosticsettings"; c := 1]) == 0
}

azure_attribute_absence["diagonstic_log_azure_eventhub_namespaces"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.eventhub/namespaces")
}

azure_attribute_absence["diagonstic_log_azure_eventhub_namespaces"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not resource.properties.logs
}

diagonstic_log_azure_eventhub_namespaces {
    lower(input.resources[_].type) == "microsoft.eventhub/namespaces"
    not azure_attribute_absence["diagonstic_log_azure_eventhub_namespaces"]
}

diagonstic_log_azure_eventhub_namespaces = false {
	lower(input.resources[_].type) == "microsoft.eventhub/namespaces"
    azure_attribute_absence["diagonstic_log_azure_eventhub_namespaces"]
}

diagonstic_log_azure_eventhub_namespaces_err = "Azure Event Hub Namespaces diagnostics logging is currently not enabled" {
	lower(input.resources[_].type) == "microsoft.eventhub/namespaces"
	azure_attribute_absence["diagonstic_log_azure_eventhub_namespaces"]
}

diagonstic_log_azure_eventhub_namespaces_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-025",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Event Hub Namespaces diagnostic logs should be enabled",
    "Policy Description": "Diagnostic settings for Azure Event Hub Namespaces used to stream resource logs to a Log Analytics workspace. this policy will identify any Azure Event Hub Namespaces which has this diagnostic settings missing or misconfigured.",
    "Resource Type": "Microsoft.EventHub/namespaces",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.eventhub/namespaces?pivots=deployment-language-arm-template"
}


#
# PR-AZR-ARM-MNT-026
#

default azure_recoveryservices_vaults_diagonstic_log_steam_to_log_analytics_workspaces = null

azure_attribute_absence ["azure_recoveryservices_vaults_diagonstic_log_steam_to_log_analytics_workspaces"] {
    count([c | lower(input.resources[_].type) == "microsoft.insights/diagnosticsettings"; c := 1]) == 0
}

azure_attribute_absence["azure_recoveryservices_vaults_diagonstic_log_steam_to_log_analytics_workspaces"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not contains(lower(resource.scope), "microsoft.recoveryservices/vaults")
}

azure_attribute_absence["azure_recoveryservices_vaults_diagonstic_log_steam_to_log_analytics_workspaces"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    not resource.properties.workspaceId
}

azure_issue["azure_recoveryservices_vaults_diagonstic_log_steam_to_log_analytics_workspaces"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/diagnosticsettings"
    count(resource.properties.workspaceId) == 0
}

azure_recoveryservices_vaults_diagonstic_log_steam_to_log_analytics_workspaces {
    lower(input.resources[_].type) == "microsoft.recoveryservices/vaults"
    not azure_attribute_absence["azure_recoveryservices_vaults_diagonstic_log_steam_to_log_analytics_workspaces"]
    not azure_issue["azure_recoveryservices_vaults_diagonstic_log_steam_to_log_analytics_workspaces"]
}

azure_recoveryservices_vaults_diagonstic_log_steam_to_log_analytics_workspaces = false {
	lower(input.resources[_].type) == "microsoft.recoveryservices/vaults"
    azure_issue["azure_recoveryservices_vaults_diagonstic_log_steam_to_log_analytics_workspaces"]
}

azure_recoveryservices_vaults_diagonstic_log_steam_to_log_analytics_workspaces = false {
	lower(input.resources[_].type) == "microsoft.recoveryservices/vaults"
    azure_attribute_absence["azure_recoveryservices_vaults_diagonstic_log_steam_to_log_analytics_workspaces"]
}

azure_recoveryservices_vaults_diagonstic_log_steam_to_log_analytics_workspaces_err = "'microsoft.recoveryservices/vaults' diagnostics logging 'microsoft.insights/diagnosticsettings' dont have any 'workspaceId' property configured" {
	lower(input.resources[_].type) == "microsoft.recoveryservices/vaults"
	azure_attribute_absence["azure_recoveryservices_vaults_diagonstic_log_steam_to_log_analytics_workspaces"]
} else = "Azure Recovery Services Vault diagnostics logging is currently not configured to stream diagnostic settings to Log Analytics workspace" {
    lower(input.resources[_].type) == "microsoft.recoveryservices/vaults"
	azure_issue["azure_recoveryservices_vaults_diagonstic_log_steam_to_log_analytics_workspaces"]
}

azure_recoveryservices_vaults_diagonstic_log_steam_to_log_analytics_workspaces_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-026",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Recovery Services Vault Diagnostic Settings stream to Log Analytics workspace",
    "Policy Description": "Audit Diagnostic Settings for Recovery Services Vault to stream to Log Analytics workspace for Resource specific categories. If any of the Resource specific categories are not enabled, Recovery Services Vault is put on audit.",
    "Resource Type": "Microsoft.RecoveryServices/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.recoveryservices/vaults?pivots=deployment-language-arm-template"
}