



# Master Test ID: PR-AZR-TRF-STR-009


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(storageaccounts.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-STR-009|
|eval: |data.rule.region|
|message: |data.rule.region_err|
|remediationDescription: |In 'azurerm_storage_account' resource, set value as 'northeurope' or 'westeurope' in property 'location' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#location' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_STR_009.py|


severity: High

title: Storage Accounts location configuration should be inside of Europe

description: Identify Storage Accounts outside of the following regions: northeurope, westeurope  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['GDPR']|
|service: |['terraform']|


resourceTypes: ['azurerm_storage_account']


[file(storageaccounts.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego
