



# Title: Storage Accounts should use a virtual network service endpoint


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-STR-023

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-STR-023|
|eval|data.rule.storage_acl_usage_vnet|
|message|data.rule.storage_acl_usage_vnet_err|
|remediationDescription|In 'azurerm_storage_account_network_rules' resource or 'azurerm_storage_account's inner block 'network_rules', set 'default_action = Deny' and set id of target 'azurerm_subnet' into property 'virtual_network_subnet_ids' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules#virtual_network_subnet_ids' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_STR_023.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy audits any Storage Account not configured to use a virtual network service endpoint.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_storage_account', 'azurerm_storage_account_network_rules']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego
