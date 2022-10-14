



# Title: Ensure Azure Redis Cache has latest version of tls configured


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-ARC-007

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Redis.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-ARC-007|
|eval|data.rule.min_tls_version_redis|
|message|data.rule.min_tls_version_redis_err|
|remediationDescription|In Resource of type 'Microsoft.Cache/redis' make sure properties.minimumTlsVersion exists and value is set to '1.2'.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_ARC_007.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy will identify the Azure Redis Cache which doesn't have the latest version of tls configured and give the alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.cache/redis']


[Redis.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/Redis.rego
