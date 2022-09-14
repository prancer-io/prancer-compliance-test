



# Master Test ID: PR-AZR-TRF-KV-001


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(KeyVault.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-KV-001|
|eval: |data.rule.KeyVault|
|message: |data.rule.KeyVault_err|
|remediationDescription: |In 'azurerm_key_vault' resource, make sure you have added either 'key_permissions' or 'secret_permissions' or 'certificate_permissions' or 'storage_permissions' under access_policy block to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#access_policy' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_KV_001.py|


severity: Low

title: Ensure at least one principal has access to Keyvault

description: Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice', 'HIPAA', 'NIST CSF']|
|service: |['terraform']|


resourceTypes: ['azurerm_key_vault']


[file(KeyVault.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego
