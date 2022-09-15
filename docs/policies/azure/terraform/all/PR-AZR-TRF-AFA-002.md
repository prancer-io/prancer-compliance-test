



# Master Test ID: PR-AZR-TRF-AFA-002


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([functionapp.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-AFA-002|
|eval|data.rule.functionapp_not_accessible_from_all_region|
|message|data.rule.functionapp_not_accessible_from_all_region_err|
|remediationDescription|In 'azurerm_function_app' resource, make sure 'allowed_origins' dont have '*' as item under 'cors' block under 'site_config' to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app#allowed_origins' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_AFA_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Azure Function apps should not be accessible from all regions

***<font color="white">Description:</font>*** This policy will identify Azure Function Apps which allows accessibility from all region and give alert if found.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_function_app']


[functionapp.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/functionapp.rego
