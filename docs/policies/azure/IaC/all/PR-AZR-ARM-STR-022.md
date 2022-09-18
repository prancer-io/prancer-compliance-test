



# Title: Storage account encryption scopes should use customer-managed keys to encrypt data at rest


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-STR-022

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-STR-022|
|eval|data.rule.storage_account_encryption_scopes_source|
|message|data.rule.storage_account_encryption_scopes_source_err|
|remediationDescription|In 'microsoft.storage/storageaccounts/encryptionscopes' resource, set source = 'microsoft.keyvault' to fix the issue.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/encryptionscopes' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_STR_022.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Use customer-managed keys to manage the encryption at the rest of your storage account encryption scopes. Customer-managed keys enable the data to be encrypted with an Azure key-vault key created and owned by you. You have full control and responsibility for the key lifecycle, including rotation and management. Learn more about storage account encryption scopes at https://aka.ms/encryption-scopes-overview.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.storage/storageaccounts']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/storageaccounts.rego
