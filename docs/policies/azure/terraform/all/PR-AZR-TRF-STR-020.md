



# Master Test ID: PR-AZR-TRF-STR-020


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-STR-020|
|eval|data.rule.storage_account_uses_double_encryption|
|message|data.rule.storage_account_uses_double_encryption_err|
|remediationDescription|'azurerm_storage_account' resource need to have a link with 'azurerm_storage_encryption_scope', set 'id' of 'azurerm_storage_account' to property 'storage_account_id' under 'azurerm_storage_encryption_scope' resource to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_encryption_scope#storage_account_id' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_STR_020.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Storage account encryption scopes should use double encryption for data at rest

***<font color="white">Description:</font>*** Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_storage_account', 'azurerm_storage_encryption_scope']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego
