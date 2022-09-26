



# Title: Azure Cache for Redis should disable public network access


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-ARC-003

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_420']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Redis.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-ARC-003|
|eval|data.rule.redis_public_access|
|message|data.rule.redis_public_access_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/azure-cache-for-redis/cache-private-link' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_ARC_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Disabling public network access improves security by ensuring that the Azure Cache for Redis isn't exposed on the public internet. You can limit exposure of your Azure Cache for Redis by creating private endpoints instead. Learn more at: https://docs.microsoft.com/azure/azure-cache-for-redis/cache-private-link.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Databases']|



[Redis.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/Redis.rego
