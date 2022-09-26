



# Title: Azure KeyVault should use private link


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-KV-009

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([KeyVault.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-KV-009|
|eval|data.rule.kv_usage_private_enpoint|
|message|data.rule.kv_usage_private_enpoint_err|
|remediationDescription|'azurerm_key_vault' resource need to have a link with 'azurerm_private_endpoint', set 'id' of 'azurerm_key_vault' to property 'private_connection_resource_id' under 'azurerm_private_endpoint' resources 'private_service_connection' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint#private_connection_resource_id' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_KV_009.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure KeyVault, data leakage risks are reduced.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_key_vault', 'azurerm_private_endpoint']


[KeyVault.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego
