



# Title: Storage account encryption scopes should have infrastructure encryption


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-STR-021

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-STR-021|
|eval|data.rule.storage_account_scopes_require_encryption|
|message|data.rule.storage_account_scopes_require_encryption_err|
|remediationDescription|In 'microsoft.storage/storageaccounts/encryptionscopes' resource, set requireInfrastructureEncryption = 'true' to fix the issue.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/encryptionscopes' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_STR_021.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Enable infrastructure encryption for encryption at the rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.storage/storageaccounts']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/storageaccounts.rego
