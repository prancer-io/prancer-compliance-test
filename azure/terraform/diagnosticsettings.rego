package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting
#
# PR-AZR-TRF-MNT-002
#

default log_keyvault = null

azure_attribute_absence ["log_keyvault"] {
    count([c | input.resources[_].type == "azurerm_monitor_diagnostic_setting"; c := 1]) == 0
}

# azure_issue["log_keyvault"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_monitor_diagnostic_setting"
#     log := resource.properties.log[_]
#     lower(log.category) == "auditevent"
#     log.enabled == false
# }

azure_issue ["log_keyvault"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
    count([c | r := input.resources[_];
              r.type == "azurerm_monitor_diagnostic_setting";
              contains(r.properties.target_resource_id, resource.properties.compiletime_identity);
              # as per Farshid: for now we should not check this enabled or category property as log is an array and possiblility that one can be enabled and other can be disabled. which will mislead us. 
              #r.properties.log[_].enabled == true;
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_monitor_diagnostic_setting";
              contains(r.properties.target_resource_id, concat(".", [resource.type, resource.name]));
              #r.properties.log[_].enabled == true;
              c := 1]) == 0
}

log_keyvault = false {
    lower(input.resources[_].type) == "azurerm_key_vault"
    azure_attribute_absence["log_keyvault"]
}

log_keyvault {
    lower(input.resources[_].type) == "azurerm_key_vault"
    not azure_attribute_absence["log_keyvault"]
    not azure_issue["log_keyvault"]
}

log_keyvault = false {
    lower(input.resources[_].type) == "azurerm_key_vault"
    azure_issue["log_keyvault"]
}


log_keyvault_err = "azurerm_key_vault's azurerm_monitor_diagnostic_setting and its property block 'log' need to be exist. its currently missing from the resource." {
    lower(input.resources[_].type) == "azurerm_key_vault"
    azure_attribute_absence["log_keyvault"]
} else = "Azure Key Vault audit logging is currently not enabled" {
    lower(input.resources[_].type) == "azurerm_key_vault"
    azure_issue["log_keyvault"] 
}

log_keyvault_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Key Vault audit logging should be enabled",
    "Policy Description": "This policy identifies Azure Key Vault instances for which audit logging is disabled. As a best practice, enable audit event logging for Key Vault instances to monitor how and when your key vaults are accessed, and by whom.",
    "Resource Type": "azurerm_monitor_diagnostic_setting",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting"
}


#
# PR-AZR-TRF-MNT-003
#

default log_lbs = null

azure_attribute_absence ["log_lbs"] {
    count([c | input.resources[_].type == "azurerm_lb"; c := 1]) != count([c | input.resources[_].type == "azurerm_monitor_diagnostic_setting"; c := 1])
}

#azure_attribute_absence["log_lbs"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_lb"
#    count([c | input.resources[_].type == "azurerm_monitor_diagnostic_setting";
#    	   c := 1]) == 0
#}

azure_attribute_absence["log_lbs"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_diagnostic_setting"
    not resource.properties.log
}

#azure_issue["log_lbs"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_monitor_diagnostic_setting"
#    not contains(lower(resource.properties.target_resource_id), "microsoft.network/loadbalancers") 
#}

azure_issue["log_lbs"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_diagnostic_setting"
    log := resource.properties.log[_]
    lower(log.category) == "auditevent"
    log.enabled == false
}

log_lbs {
    lower(input.resources[_].type) == "azurerm_lb"
    not azure_attribute_absence["log_lbs"]
    not azure_issue["log_lbs"]
}

log_lbs = false {
    lower(input.resources[_].type) == "azurerm_lb"
    azure_issue["log_lbs"]
}

log_lbs = false {
    lower(input.resources[_].type) == "azurerm_lb"
    azure_attribute_absence["log_lbs"]
}

log_lbs_err = "azurerm_lb's azurerm_monitor_diagnostic_setting property block 'log' need to be exist. its currently missing from the resource." {
    lower(input.resources[_].type) == "azurerm_lb"
    azure_attribute_absence["log_lbs"]
} else = "Azure Load Balancer diagnostics logging is currently not enabled" {
    lower(input.resources[_].type) == "azurerm_lb"
    azure_issue["log_lbs"] 
}

log_lbs_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Load Balancer diagnostic logs should be enabled",
    "Policy Description": "Azure Load Balancers provide different types of logsâ€”alert events, health probe, metricsâ€”to help you manage and troubleshoot issues. This policy identifies Azure Load Balancers that have diagnostics logs disabled. As a best practice, enable diagnostic logs to start collecting the data available through these logs.",
    "Resource Type": "azurerm_monitor_diagnostic_setting",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting"
}


# https://github.com/hashicorp/terraform-provider-azurerm/issues/8275
# PR-AZR-TRF-MNT-004
#

default log_storage_retention = null

azure_attribute_absence ["log_storage_retention"] {
    count([c | input.resources[_].type == "azurerm_storage_account"; c := 1]) != count([c | input.resources[_].type == "azurerm_monitor_diagnostic_setting"; c := 1])
}

#azure_attribute_absence["log_storage_retention"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_storage_account"
#    count([c | input.resources[_].type == "azurerm_monitor_diagnostic_setting";
#    	   c := 1]) == 0
#}

azure_attribute_absence["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_diagnostic_setting"
    not resource.properties.log
}

#azure_issue["log_storage_retention"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_monitor_diagnostic_setting"
#    not contains(lower(resource.properties.target_resource_id), "microsoft.storage/storageaccounts") 
#}

azure_issue["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_diagnostic_setting"
    log := resource.properties.log[_]
    lower(log.category) == "auditevent"
    log.enabled == false
}

azure_issue["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_diagnostic_setting"
    log := resource.properties.log[_]
    lower(log.category) == "auditevent"
    retention_policy := log.retention_policy[_]
    retention_policy.enabled == false
}

azure_issue["log_storage_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_diagnostic_setting"
    log := resource.properties.log[_]
    lower(log.category) == "auditevent"
    retention_policy := log.retention_policy[_]
    to_number(retention_policy.days) < 90
}

log_storage_retention {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_attribute_absence["log_storage_retention"]
    not azure_issue["log_storage_retention"]
}

log_storage_retention = false {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_issue["log_storage_retention"]
}

log_storage_retention = false {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_attribute_absence["log_storage_retention"]
}

log_storage_retention_err = "azurerm_storage_account's azurerm_monitor_diagnostic_setting property block 'log' and 'log.retention_policy' need to be exist. one or both are currently missing from the resource." {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_attribute_absence["log_storage_retention"]
} else = "Azure Storage Account with Auditing Retention is currently less than 90 days. Its need to be 90 days or more" {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_issue["log_storage_retention"]
}

log_storage_retention_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Storage Account auditing retention should be 90 days or more",
    "Policy Description": "This policy identifies Storage Accounts which have Auditing Retentions less than 90 days. Audit Logs can be used to check for anomalies and gives insight into suspected breaches or misuse of information and access. It is recommended to configure Storage Account Audit Log Retention to be greater than or equal to 90 days.",
    "Resource Type": "azurerm_monitor_diagnostic_setting",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting"
}

# https://github.com/hashicorp/terraform-provider-azurerm/issues/8275
# PR-AZR-TRF-MNT-005
#

default log_blob = null

azure_attribute_absence ["log_blob"] {
    count([c | input.resources[_].type == "azurerm_storage_blob"; c := 1]) != count([c | input.resources[_].type == "azurerm_monitor_diagnostic_setting"; c := 1])
}

#azure_attribute_absence["log_blob"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_storage_blob"
#    count([c | input.resources[_].type == "azurerm_monitor_diagnostic_setting";
#    	   c := 1]) == 0
#}

azure_attribute_absence["log_blob"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_diagnostic_setting"
    not resource.properties.log
}

#azure_issue["log_blob"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_monitor_diagnostic_setting"
#    not contains(lower(resource.properties.target_resource_id), "microsoft.storage/storageaccounts/blobservices") 
#}

azure_issue["log_blob"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_diagnostic_setting"
    log := resource.properties.log[_]
    lower(log.category) == "auditevent"
    log.enabled == false
}

log_blob {
    lower(input.resources[_].type) == "azurerm_storage_blob"
    not azure_attribute_absence["log_blob"]
    not azure_issue["log_blob"]
}

log_blob = false {
    lower(input.resources[_].type) == "azurerm_storage_blob"
    azure_issue["log_blob"]
}

log_blob = false {
    lower(input.resources[_].type) == "azurerm_storage_blob"
    azure_attribute_absence["log_blob"]
}

log_blob_err = "azurerm_storage_blob's azurerm_monitor_diagnostic_setting property block 'log' need to be exist. Its currently missing from the resource." {
    lower(input.resources[_].type) == "azurerm_storage_blob"
    azure_attribute_absence["log_blob"]
} else = "Azure storage account blob services diagnostic logs is currently not enabled" {
    lower(input.resources[_].type) == "azurerm_storage_blob"
    azure_issue["log_blob"]
}

log_blob_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure storage account blob services diagnostic logs should be enabled",
    "Policy Description": "Storage Logging records details of requests (read, write, and delete operations) against your Azure blobs. The logs include additional information such as:<br>- Timing and server latency.<br>- Success or failure, and HTTP status code.<br>- Authentication details<br><br>This policy identifies Azure storage accounts that do not have logging enabled for blobs. As a best practice, enable logging for read, write, and delete request types on blobs.",
    "Resource Type": "azurerm_monitor_diagnostic_setting",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting"
}

# https://github.com/hashicorp/terraform-provider-azurerm/issues/8275
# PR-AZR-TRF-MNT-006
#

default log_queue = null

azure_attribute_absence ["log_queue"] {
    count([c | input.resources[_].type == "azurerm_storage_queue"; c := 1]) != count([c | input.resources[_].type == "azurerm_monitor_diagnostic_setting"; c := 1])
}

#azure_attribute_absence["log_queue"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_storage_queue"
#    count([c | input.resources[_].type == "azurerm_monitor_diagnostic_setting";
#    	   c := 1]) == 0
#}

azure_attribute_absence["log_queue"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_diagnostic_setting"
    not resource.properties.log
}

#azure_issue["log_queue"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_monitor_diagnostic_setting"
#    not contains(lower(resource.properties.target_resource_id), "microsoft.storage/storageaccounts/queueservices") 
#}

azure_issue["log_queue"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_diagnostic_setting"
    log := resource.properties.log[_]
    lower(log.category) == "auditevent"
    log.enabled == false
}

log_queue {
    lower(input.resources[_].type) == "azurerm_storage_queue"
    not azure_attribute_absence["log_queue"]
    not azure_issue["log_queue"]
}

log_queue = false {
    lower(input.resources[_].type) == "azurerm_storage_queue"
    azure_issue["log_queue"]
}

log_queue = false {
    lower(input.resources[_].type) == "azurerm_storage_queue"
    azure_attribute_absence["log_queue"]
}

log_queue_err = "azurerm_storage_queue's azurerm_monitor_diagnostic_setting property block 'log' need to be exist. Its currently missing from the resource." {
    lower(input.resources[_].type) == "azurerm_storage_queue"
    azure_attribute_absence["log_queue"]
} else = "Azure storage account queue services diagnostic logs is currently not enabled" {
    lower(input.resources[_].type) == "azurerm_storage_queue"
    azure_issue["log_queue"]
}

log_queue_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure storage account queue services diagnostic logs should be enabled",
    "Policy Description": "Storage Logging records details of requests (read, write, and delete operations) against your Azure queues. The logs include additional information such as:<br>- Timing and server latency.<br>- Success or failure, and HTTP status code.<br>- Authentication details<br><br>This policy identifies Azure storage accounts that do not have logging enabled for queues. As a best practice, enable logging for read, write, and delete request types on queues.",
    "Resource Type": "azurerm_monitor_diagnostic_setting",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting"
}

# https://github.com/hashicorp/terraform-provider-azurerm/issues/8275
# PR-AZR-TRF-MNT-007
#

default log_table = null

azure_attribute_absence ["log_table"] {
    count([c | input.resources[_].type == "azurerm_storage_table"; c := 1]) != count([c | input.resources[_].type == "azurerm_monitor_diagnostic_setting"; c := 1])
}

#azure_attribute_absence["log_table"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_storage_table"
#    count([c | input.resources[_].type == "azurerm_monitor_diagnostic_setting";
#    	   c := 1]) == 0
#}

azure_attribute_absence["log_table"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_diagnostic_setting"
    not resource.properties.log
}

#azure_issue["log_table"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_monitor_diagnostic_setting"
#    not contains(lower(resource.properties.target_resource_id), "microsoft.storage/storageaccounts/tableservices") 
#}

azure_issue["log_table"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_diagnostic_setting"
    log := resource.properties.log[_]
    lower(log.category) == "auditevent"
    log.enabled == false
}

log_table {
    lower(input.resources[_].type) == "azurerm_storage_table"
    not azure_attribute_absence["log_table"]
    not azure_issue["log_table"]
}

log_table = false {
    lower(input.resources[_].type) == "azurerm_storage_table"
    azure_issue["log_table"]
}

log_table = false {
    lower(input.resources[_].type) == "azurerm_storage_table"
    azure_attribute_absence["log_table"]
}

log_table_err = "azurerm_storage_table's azurerm_monitor_diagnostic_setting property block 'log' need to be exist. Its currently missing from the resource." {
    lower(input.resources[_].type) == "azurerm_storage_table"
    azure_attribute_absence["log_table"]
} else = "Azure storage account table services diagnostic logs is currently not enabled" {
    lower(input.resources[_].type) == "azurerm_storage_table"
    azure_issue["log_table"]
}

log_table_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-007",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure storage account table services diagnostic logs should be enabled",
    "Policy Description": "Storage Logging records details of requests (read, write, and delete operations) against your Azure queues. The logs include additional information such as:<br>- Timing and server latency.<br>- Success or failure, and HTTP status code.<br>- Authentication details<br><br>This policy identifies Azure storage accounts that do not have logging enabled for tables. As a best practice, enable logging for read, write, and delete request types on tables.",
    "Resource Type": "azurerm_monitor_diagnostic_setting",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting"
}
