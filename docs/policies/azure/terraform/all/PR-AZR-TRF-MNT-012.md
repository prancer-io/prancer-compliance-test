



# Title: Redis Cache diagnostic logs should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-MNT-012

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([diagnosticsettings.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-MNT-012|
|eval|data.rule.redis_cache_diagonstic_log_enabled|
|message|data.rule.redis_cache_diagonstic_log_enabled_err|
|remediationDescription|In 'azurerm_monitor_diagnostic_setting' resource, make sure 'log' block exist and 'target_resource_id' contains id of target 'azurerm_redis_cache' resource to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting#log' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_MNT_012.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Diagnostic settings for redis cache used to stream resource logs to a Log Analytics workspace. this policy will identify any storage account which has this diagnostic settings missing or misconfigured.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_redis_cache', 'azurerm_monitor_diagnostic_setting']


[diagnosticsettings.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/diagnosticsettings.rego
