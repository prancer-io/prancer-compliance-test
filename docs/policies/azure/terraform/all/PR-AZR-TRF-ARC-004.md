



# Master Test ID: PR-AZR-TRF-ARC-004


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(Redis.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-ARC-004|
|eval: |data.rule.redis_cache_inside_vnet|
|message: |data.rule.redis_cache_inside_vnet_err|
|remediationDescription: |In 'azurerm_redis_cache' resource, set 'id' of target 'azurerm_subnet' into property 'subnet_id' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache#subnet_id' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_ARC_004.py|


severity: High

title: Azure Cache for Redis should reside within a virtual network

description: Azure Virtual Network deployment provides enhanced security and isolation for your Azure Cache for Redis, as well as subnets, access control policies, and other features to further restrict access.When an Azure Cache for Redis instance is configured with a virtual network, it is not publicly addressable and can only be accessed from virtual machines and applications within the virtual network.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_redis_cache']


[file(Redis.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/Redis.rego
