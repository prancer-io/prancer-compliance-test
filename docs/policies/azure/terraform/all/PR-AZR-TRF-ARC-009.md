



# Master Test ID: PR-AZR-TRF-ARC-009


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(Redis.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-ARC-009|
|eval: |data.rule.redis_cache_uses_private_dns_zone|
|message: |data.rule.redis_cache_uses_private_dns_zone_err|
|remediationDescription: |In 'azurerm_private_dns_zone_virtual_network_link' resource, at property 'virtual_network_id' set id of the azurerm_virtual_network where azurerm_redis_cache exist and at property 'private_dns_zone_name' set target azurerm_private_dns_zone name to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_dns_zone_virtual_network_link' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_ARC_009.py|


severity: High

title: Azure Cache for Redis should configure to use private DNS zone

description: Use private DNS zones to override the DNS resolution for a private endpoint. A private DNS zone can be linked to your virtual network to resolve to Azure Cache for Redis.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_redis_cache', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_private_dns_zone_virtual_network_link', 'azurerm_private_dns_zone']


[file(Redis.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/Redis.rego
