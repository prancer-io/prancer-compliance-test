



# Master Test ID: PR-AZR-TRF-DSK-002


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(disks.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-DSK-002|
|eval: |data.rule.disk_encrypt_cmk|
|message: |data.rule.disk_encrypt_cmk_err|
|remediationDescription: |In 'azurerm_managed_disk' resource, set id of target 'azurerm_disk_encryption_set' as value to 'disk_encryption_set_id' property to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/managed_disk#enabled' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_DSK_002.py|


severity: High

title: Azure disk should have CMK disk encryption enabled

description: SSE with CMK is integrated with Azure Key Vault, which provides highly available and scalable secure storage for your keys backed by Hardware Security Modules. You can either bring your own keys (BYOK) to your Key Vault or generate new keys in the Key Vault. For more information, see https://azure.microsoft.com/en-in/blog/announcing-serverside-encryption-with-customermanaged-keys-for-azure-managed-disks/  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service: |['terraform']|


resourceTypes: ['azurerm_managed_disk', 'azurerm_disk_encryption_set']


[file(disks.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/disks.rego
