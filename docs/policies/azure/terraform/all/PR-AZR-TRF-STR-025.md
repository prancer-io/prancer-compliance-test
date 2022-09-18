



# Title: Azure Storage Account File Share should use SMB protocol


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-STR-025

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-STR-025|
|eval|data.rule.storage_account_file_share_usage_smb_protocol|
|message|data.rule.storage_account_file_share_usage_smb_protocol_err|
|remediationDescription|In 'azurerm_storage_share' resource, set enabled_protocol = 'SMB' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_share#enabled_protocol' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_STR_025.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** The Server Message Block (SMB) protocol is a network file sharing protocol that allows applications on a computer to read and write to files and to request services from server programs in a computer network. The SMB protocol can be used on top of its TCP/IP protocol or other network protocols.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_storage_share']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego
