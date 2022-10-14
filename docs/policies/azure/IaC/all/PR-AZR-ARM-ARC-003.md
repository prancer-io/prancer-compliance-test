



# Title: Azure Cache for Redis should disable public network access


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-ARC-003

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Redis.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-ARC-003|
|eval|data.rule.redis_public_access|
|message|data.rule.redis_public_access_err|
|remediationDescription|In Resource of type 'Microsoft.Cache/redis' make sure properties.publicNetworkAccess value is set to 'disabled'.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_ARC_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Disabling public network access improves security by ensuring that the Azure Cache for Redis isn't exposed on the public internet. You can limit exposure of your Azure Cache for Redis by creating private endpoints instead. Learn more at: https://docs.microsoft.com/azure/azure-cache-for-redis/cache-private-link.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.cache/redis/linkedservers', 'microsoft.cache/redis']


[Redis.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/Redis.rego
