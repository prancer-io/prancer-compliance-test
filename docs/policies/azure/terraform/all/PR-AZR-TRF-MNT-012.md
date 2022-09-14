



# Master Test ID: PR-AZR-TRF-MNT-012


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(diagnosticsettings.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-MNT-012|
|eval: |data.rule.redis_cache_diagonstic_log_enabled|
|message: |data.rule.redis_cache_diagonstic_log_enabled_err|
|remediationDescription: |In 'azurerm_monitor_diagnostic_setting' resource, make sure 'log' block exist and 'target_resource_id' contains id of target 'azurerm_redis_cache' resource to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting#log' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_MNT_012.py|


severity: Medium

title: Redis Cache diagnostic logs should be enabled

description: Diagnostic settings for redis cache used to stream resource logs to a Log Analytics workspace. this policy will identify any storage account which has this diagnostic settings missing or misconfigured.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_redis_cache', 'azurerm_monitor_diagnostic_setting']


[file(diagnosticsettings.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/diagnosticsettings.rego
