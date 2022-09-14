



# Master Test ID: PR-AZR-TRF-STR-025


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(storageaccounts.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-STR-025|
|eval: |data.rule.storage_account_file_share_usage_smb_protocol|
|message: |data.rule.storage_account_file_share_usage_smb_protocol_err|
|remediationDescription: |In 'azurerm_storage_share' resource, set enabled_protocol = 'SMB' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_share#enabled_protocol' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_STR_025.py|


severity: High

title: Azure Storage Account File Share should use SMB protocol

description: The Server Message Block (SMB) protocol is a network file sharing protocol that allows applications on a computer to read and write to files and to request services from server programs in a computer network. The SMB protocol can be used on top of its TCP/IP protocol or other network protocols.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_storage_share']


[file(storageaccounts.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego
