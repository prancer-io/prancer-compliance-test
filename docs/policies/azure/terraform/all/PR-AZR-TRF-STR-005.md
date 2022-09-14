



# Master Test ID: PR-AZR-TRF-STR-005


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(storageaccounts.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-STR-005|
|eval: |data.rule.storage_threat_protection|
|message: |data.rule.storage_threat_protection_err|
|remediationDescription: |In 'azurerm_advanced_threat_protection' resource, set 'enabled = true' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/advanced_threat_protection#enabled' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_STR_005.py|


severity: Medium

title: Advanced Threat Protection should be enabled for storage account

description: Advanced Threat Protection should be enabled for all the storage accounts  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service: |['terraform']|


resourceTypes: ['azurerm_advanced_threat_protection', 'azurerm_storage_account']


[file(storageaccounts.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego
