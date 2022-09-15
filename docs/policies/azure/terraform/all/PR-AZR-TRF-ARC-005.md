



# Master Test ID: PR-AZR-TRF-ARC-005


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Redis.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-ARC-005|
|eval|data.rule.redis_cache_uses_privatelink|
|message|data.rule.redis_cache_uses_privatelink_err|
|remediationDescription|'azurerm_redis_cache' resource subnet need to have ip configured with with azurerm_private_link_service and this need to have a link with 'azurerm_private_endpoint', set 'id' of 'azurerm_private_link_service' (which has ip configured for redis cache subnet) to property 'private_connection_resource_id' under 'azurerm_private_endpoint' resources 'private_service_connection' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint#private_connection_resource_id' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_ARC_005.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Azure Cache for Redis should use private link

***<font color="white">Description:</font>*** Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Cache for Redis instances, data leakage risks are reduced.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_redis_cache', 'azurerm_subnet', 'azurerm_virtual_network', 'azurerm_lb', 'azurerm_private_link_service', 'azurerm_public_ip', 'azurerm_private_endpoint']


[Redis.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/Redis.rego
