



# Master Test ID: PR-AZR-TRF-ARC-006


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(Redis.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-ARC-006|
|eval: |data.rule.redis_persistence_enabled|
|message: |data.rule.redis_persistence_enabled_err|
|remediationDescription: | In 'azurerm_redis_cache' resource, set 'rdb_backup_enabled = true' under 'redis_configuration' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache#rdb_backup_enabled' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_ARC_006.py|


severity: High

title: Ensure Persistence is enabled on Redis Cache to Perform complete system backups

description: Enable Redis persistence. Redis persistence allows you to persist data stored in Redis. You can also take snapshots and back up the data, which you can load in case of a hardware failure. This is a huge advantage over Basic or Standard tier where all the data is stored in memory and there can be potential data loss in case of a failure where Cache nodes are down.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_redis_cache']


[file(Redis.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/Redis.rego
