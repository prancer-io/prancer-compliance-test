



# Title: Storage account encryption scopes should use customer-managed keys to encrypt data at rest


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-STR-022

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_301']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-STR-022|
|eval|data.rule.storage_account_encryption_scopes_source|
|message|data.rule.storage_account_encryption_scopes_source_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/storage/common/customer-managed-keys-overview' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_STR_022.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Use customer-managed keys to manage the encryption at the rest of your storage account encryption scopes. Customer-managed keys enable the data to be encrypted with an Azure key-vault key created and owned by you. You have full control and responsibility for the key lifecycle, including rotation and management. Learn more about storage account encryption scopes at https://aka.ms/encryption-scopes-overview.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|Azure|
|compliance|['Best Practice']|
|service|['Storage']|



[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/storageaccounts.rego
