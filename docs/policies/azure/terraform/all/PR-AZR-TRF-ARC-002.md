



# Master Test ID: PR-AZR-TRF-ARC-002


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(Redis.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-ARC-002|
|eval: |data.rule.serverRole|
|message: |data.rule.serverRole_err|
|remediationDescription: |In 'azurerm_redis_linked_server' resource, set server_role = 'Secondary' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_linked_server#server_role' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_ARC_002.py|


severity: Medium

title: Redis cache should have a backup

description: Replicate Redis Cache server data to another Redis Cache server using geo replication. This feature is only available for Premium tier Redis Cache. From performance point of view, Microsoft recommends that both Redis Caches (Primary and the linked secondary) reside in the same region.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_redis_linked_server', 'azurerm_redis_cache']


[file(Redis.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/Redis.rego
