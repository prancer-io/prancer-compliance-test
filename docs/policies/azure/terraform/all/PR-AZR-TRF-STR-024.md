



# Master Test ID: PR-AZR-TRF-STR-024


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-STR-024|
|eval|data.rule.storage_shared_access_key_disabled|
|message|data.rule.storage_shared_access_key_disabled_err|
|remediationDescription|In 'azurerm_storage_account' resource, set 'shared_access_key_enabled = false' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#shared_access_key_enabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_STR_024.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Storage accounts should prevent shared key access

***<font color="white">Description:</font>*** Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_storage_account']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego
