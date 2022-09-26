



# Title: Azure Storage Account diagnostic logs should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-MNT-008

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([diagnosticsettings.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-MNT-008|
|eval|data.rule.storage_account_diagonstic_log_enabled|
|message|data.rule.storage_account_diagonstic_log_enabled_err|
|remediationDescription|In 'azurerm_monitor_diagnostic_setting' resource, make sure 'log' block exist and 'target_resource_id' contains id of target 'azurerm_storage_account' resource to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting#log' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_MNT_008.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Diagnostic settings for storage accounts used to stream resource logs to a Log Analytics workspace. this policy will identify any storage account which has this diagnostic settings missing or misconfigured.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_storage_account', 'azurerm_monitor_diagnostic_setting']


[diagnosticsettings.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/diagnosticsettings.rego
