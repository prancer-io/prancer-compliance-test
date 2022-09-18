



# Title: Activity log profile retention should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-MNT-010

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([activitylogalerts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-MNT-010|
|eval|data.rule.log_profiles_retention_enabled|
|message|data.rule.log_profiles_retention_enabled_err|
|remediationDescription|For Resource type 'microsoft.insights/logprofiles' make sure retentionPolicy.enabled exists and the value is set to true.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/Microsoft.Insights/logprofiles' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_MNT_010.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy identifies Microsoft.Insights/logprofiles which don't have log retention enabled. Activity Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.insights/logprofiles']


[activitylogalerts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/activitylogalerts.rego
