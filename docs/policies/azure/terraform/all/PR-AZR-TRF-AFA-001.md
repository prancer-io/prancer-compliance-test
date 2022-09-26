



# Title: Azure Function apps Authentication should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-AFA-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([functionapp.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-AFA-001|
|eval|data.rule.functionapp_authentication_enabled|
|message|data.rule.functionapp_authentication_enabled_err|
|remediationDescription|In 'azurerm_function_app' resource, set 'enabled = true' under 'auth_settings' block to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app#enabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_AFA_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure Function app provides built-in authentication and authorization capabilities (sometimes referred to as 'Easy Auth'), so you can sign in users and access data by writing minimal or no code in your web app, RESTful API, and mobile back end, and also Azure Functions  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_function_app']


[functionapp.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/functionapp.rego
