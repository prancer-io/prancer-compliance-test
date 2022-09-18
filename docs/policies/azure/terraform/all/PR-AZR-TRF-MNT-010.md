



# Title: Activity log profile retention should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-MNT-010

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([activitylogalerts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-MNT-010|
|eval|data.rule.azure_monitor_log_profile_retention_enabled|
|message|data.rule.azure_monitor_log_profile_retention_enabled_err|
|remediationDescription|In 'azurerm_monitor_log_profile' resource, set 'enabled = true' under 'retention_policy' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile#enabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_MNT_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies azurerm_monitor_log_profile which dont have log retention enabled. Activity Logs can be used to check for anomalies and gives insight into suspected breaches or misuse of information and access.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_monitor_activity_log_alert', 'azurerm_monitor_log_profile']


[activitylogalerts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/activitylogalerts.rego
