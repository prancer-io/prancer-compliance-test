



# Title: Storage accounts should prevent shared key access


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-STR-024

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-STR-024|
|eval|data.rule.storage_account_allow_shared_key_access|
|message|data.rule.storage_account_allow_shared_key_access_err|
|remediationDescription|In 'microsoft.storage/storageaccounts' resource, set allowSharedKeyAccess = 'false' to fix the issue.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/encryptionscopes' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_STR_024.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key and is recommended by Microsoft.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.storage/storageaccounts']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/storageaccounts.rego
