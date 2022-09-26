



# Title: Azure Storage Account File Share should use SMB protocol


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-STR-025

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_301']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-STR-025|
|eval|data.rule.storage_account_file_share_usage_smb_protocol|
|message|data.rule.storage_account_file_share_usage_smb_protocol_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/storage/files/files-smb-protocol?tabs=azure-portal#smb-security-settings' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_STR_025.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The Server Message Block (SMB) protocol is a network file sharing protocol that allows applications on a computer to read and write to files and to request services from server programs in a computer network. The SMB protocol can be used on top of its TCP/IP protocol or other network protocols.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|Azure|
|compliance|['Best Practice']|
|service|['Storage']|



[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/storageaccounts.rego
