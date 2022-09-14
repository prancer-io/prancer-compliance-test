



# Master Test ID: PR-AZR-TRF-AFA-002


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(functionapp.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-AFA-002|
|eval: |data.rule.functionapp_not_accessible_from_all_region|
|message: |data.rule.functionapp_not_accessible_from_all_region_err|
|remediationDescription: |In 'azurerm_function_app' resource, make sure 'allowed_origins' dont have '*' as item under 'cors' block under 'site_config' to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app#allowed_origins' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_AFA_002.py|


severity: Medium

title: Azure Function apps should not be accessible from all regions

description: This policy will identify Azure Function Apps which allows accessibility from all region and give alert if found.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_function_app']


[file(functionapp.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/functionapp.rego
