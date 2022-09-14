



# Master Test ID: PR-AZR-TRF-KV-003


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(KeyVault.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-KV-003|
|eval: |data.rule.enablePurgeProtection|
|message: |data.rule.enablePurgeProtection_err|
|remediationDescription: |In 'azurerm_key_vault' resource, set 'purge_protection_enabled = true' to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#purge_protection_enabled' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_KV_003.py|


severity: Medium

title: Key vault should have purge protection enabled

description: The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1485 - Data Destruction']|
|service: |['terraform']|


resourceTypes: ['azurerm_key_vault']


[file(KeyVault.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego
