



# Title: Azure Storage account should use private link


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-STR-019

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-STR-019|
|eval|data.rule.storage_account_uses_privatelink|
|message|data.rule.storage_account_uses_privatelink_err|
|remediationDescription|'azurerm_storage_account' resource need to have a link with 'azurerm_private_endpoint', set 'id' of 'azurerm_storage_account' to property 'private_connection_resource_id' under 'azurerm_private_endpoint' resources 'private_service_connection' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint#private_connection_resource_id' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_STR_019.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_storage_account', 'azurerm_private_endpoint']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego
