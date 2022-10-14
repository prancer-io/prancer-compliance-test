



# Title: Azure Storage Account File Share should use SMB protocol


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-STR-025

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-STR-025|
|eval|data.rule.storage_account_file_share_usage_smb_protocol|
|message|data.rule.storage_account_file_share_usage_smb_protocol_err|
|remediationDescription|In 'Microsoft.Storage/storageAccounts/fileServices/shares' resource, set enabledProtocols = 'SMB' to fix the issue.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/fileservices/shares?tabs=json#fileshareproperties' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_STR_025.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The Server Message Block (SMB) protocol is a network file sharing protocol that allows applications on a computer to read and write to files and to request services from server programs in a computer network. The SMB protocol can be used on top of its TCP/IP protocol or other network protocols.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['Microsoft.Storage/storageAccounts/fileServices/shares']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/storageaccounts.rego
