



# Title: Ensure Redis Cache has latest version of tls configured


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-ARC-007

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Redis.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-ARC-007|
|eval|data.rule.redis_tls_has_latest_version|
|message|data.rule.redis_tls_has_latest_version_err|
|remediationDescription| In 'azurerm_redis_cache' resource, set 'minimum_tls_version' = '1.2' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache#minimum_tls_version' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_ARC_007.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy will identify the Redis Cache which doesn't have the latest version of tls configured and give alert.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_redis_cache']


[Redis.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/Redis.rego
