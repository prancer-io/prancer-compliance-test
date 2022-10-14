



# Title: Azure Cache for Redis should disable public network access


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-ARC-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Redis.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-ARC-003|
|eval|data.rule.public_network_access_disabled|
|message|data.rule.public_network_access_disabled_err|
|remediationDescription|In 'azurerm_redis_cache' resource, set 'public_network_access_enabled = false' or make sure resource 'azurerm_private_endpoint' exist to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache#public_network_access_enabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_ARC_003.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Disabling public network access improves security by ensuring that the Azure Cache for Redis isn't exposed on the public internet. You can limit exposure of your Azure Cache for Redis by creating private endpoints instead.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_redis_cache', 'azurerm_subnet', 'azurerm_virtual_network', 'azurerm_lb', 'azurerm_private_link_service', 'azurerm_public_ip', 'azurerm_private_endpoint']


[Redis.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/Redis.rego
