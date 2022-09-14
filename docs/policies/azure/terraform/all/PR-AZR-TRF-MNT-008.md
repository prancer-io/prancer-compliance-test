



# Master Test ID: PR-AZR-TRF-MNT-008


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(diagnosticsettings.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-MNT-008|
|eval: |data.rule.storage_account_diagonstic_log_enabled|
|message: |data.rule.storage_account_diagonstic_log_enabled_err|
|remediationDescription: |In 'azurerm_monitor_diagnostic_setting' resource, make sure 'log' block exist and 'target_resource_id' contains id of target 'azurerm_storage_account' resource to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting#log' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_MNT_008.py|


severity: Medium

title: Azure Storage Account diagnostic logs should be enabled

description: Diagnostic settings for storage accounts used to stream resource logs to a Log Analytics workspace. this policy will identify any storage account which has this diagnostic settings missing or misconfigured.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_storage_account', 'azurerm_monitor_diagnostic_setting']


[file(diagnosticsettings.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/diagnosticsettings.rego
