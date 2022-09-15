



# Master Test ID: PR-AZR-TRF-ARC-009


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Redis.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-ARC-009|
|eval|data.rule.redis_cache_uses_private_dns_zone|
|message|data.rule.redis_cache_uses_private_dns_zone_err|
|remediationDescription|In 'azurerm_private_dns_zone_virtual_network_link' resource, at property 'virtual_network_id' set id of the azurerm_virtual_network where azurerm_redis_cache exist and at property 'private_dns_zone_name' set target azurerm_private_dns_zone name to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_dns_zone_virtual_network_link' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_ARC_009.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Azure Cache for Redis should configure to use private DNS zone

***<font color="white">Description:</font>*** Use private DNS zones to override the DNS resolution for a private endpoint. A private DNS zone can be linked to your virtual network to resolve to Azure Cache for Redis.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_redis_cache', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_private_dns_zone_virtual_network_link', 'azurerm_private_dns_zone']


[Redis.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/Redis.rego
