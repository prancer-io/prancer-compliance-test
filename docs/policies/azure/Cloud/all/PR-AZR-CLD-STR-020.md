



# Title: Storage accounts should have infrastructure encryption


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-STR-020

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_301']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-STR-020|
|eval|data.rule.storage_account_require_encryption|
|message|data.rule.storage_account_require_encryption_err|
|remediationDescription|1. In the Azure portal, navigate to the Storage accounts page.<br>2. Choose the Add button to add a new general-purpose v2 storage account.<br>3. On the Advanced tab, locate Infrastructure encryption, and select Enabled.<br>4. Select Review + create to finish creating the storage account.|
|remediationFunction|PR_AZR_CLD_STR_020.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Enable infrastructure encryption for a higher level of assurance that the data is secure. When infrastructure encryption is enabled, data in a storage account is encrypted twice.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|Azure|
|compliance|['Best Practice']|
|service|['Storage']|



[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/storageaccounts.rego
