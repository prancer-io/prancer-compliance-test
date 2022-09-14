



# Master Test ID: PR-AZR-TRF-STR-017


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(storageaccounts.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-STR-017|
|eval: |data.rule.storage_correct_naming_convention|
|message: |data.rule.storage_correct_naming_convention_err|
|remediationDescription: |In 'azurerm_storage_account' resource, property 'name' must be between 3 and 24 characters in length and may contain numbers and lowercase letters only to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#name' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_STR_017.py|


severity: Medium

title: Ensure Storage Account naming rules are correct

description: Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS']|
|service: |['terraform']|


resourceTypes: ['azurerm_storage_account']


[file(storageaccounts.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego
