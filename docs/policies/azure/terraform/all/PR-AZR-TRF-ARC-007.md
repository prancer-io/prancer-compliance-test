



# Master Test ID: PR-AZR-TRF-ARC-007


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(Redis.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-ARC-007|
|eval: |data.rule.redis_tls_has_latest_version|
|message: |data.rule.redis_tls_has_latest_version_err|
|remediationDescription: | In 'azurerm_redis_cache' resource, set 'minimum_tls_version' = '1.2' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache#minimum_tls_version' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_ARC_007.py|


severity: High

title: Ensure Redis Cache has latest version of tls configured

description: This policy will identify the Redis Cache which doesn't have the latest version of tls configured and give alert.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_redis_cache']


[file(Redis.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/Redis.rego
