



# Title: Ensure Persistence is enabled on Redis Cache to Perform complete system backups


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-ARC-006

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Redis.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-ARC-006|
|eval|data.rule.redis_persistence_enabled|
|message|data.rule.redis_persistence_enabled_err|
|remediationDescription| In 'azurerm_redis_cache' resource, set 'rdb_backup_enabled = true' under 'redis_configuration' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache#rdb_backup_enabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_ARC_006.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Enable Redis persistence. Redis persistence allows you to persist data stored in Redis. You can also take snapshots and back up the data, which you can load in case of a hardware failure. This is a huge advantage over Basic or Standard tier where all the data is stored in memory and there can be potential data loss in case of a failure where Cache nodes are down.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_redis_cache']


[Redis.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/Redis.rego
