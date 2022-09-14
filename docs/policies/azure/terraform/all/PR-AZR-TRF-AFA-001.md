



# Master Test ID: PR-AZR-TRF-AFA-001


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(functionapp.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-AFA-001|
|eval: |data.rule.functionapp_authentication_enabled|
|message: |data.rule.functionapp_authentication_enabled_err|
|remediationDescription: |In 'azurerm_function_app' resource, set 'enabled = true' under 'auth_settings' block to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app#enabled' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_AFA_001.py|


severity: Medium

title: Azure Function apps Authentication should be enabled

description: Azure Function app provides built-in authentication and authorization capabilities (sometimes referred to as 'Easy Auth'), so you can sign in users and access data by writing minimal or no code in your web app, RESTful API, and mobile back end, and also Azure Functions  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_function_app']


[file(functionapp.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/functionapp.rego
