



# Master Test ID: PR-AZR-TRF-ARC-002


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Redis.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-ARC-002|
|eval|data.rule.serverRole|
|message|data.rule.serverRole_err|
|remediationDescription|In 'azurerm_redis_linked_server' resource, set server_role = 'Secondary' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_linked_server#server_role' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_ARC_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Redis cache should have a backup

***<font color="white">Description:</font>*** Replicate Redis Cache server data to another Redis Cache server using geo replication. This feature is only available for Premium tier Redis Cache. From performance point of view, Microsoft recommends that both Redis Caches (Primary and the linked secondary) reside in the same region.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_redis_linked_server', 'azurerm_redis_cache']


[Redis.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/Redis.rego
