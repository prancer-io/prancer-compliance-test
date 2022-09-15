



# Master Test ID: PR-AZR-TRF-WEB-006


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([appservice.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-WEB-006|
|eval|data.rule.app_service_cors_not_allowing_all|
|message|data.rule.app_service_cors_not_allowing_all_err|
|remediationDescription|In 'azurerm_app_service' resource, dont set '*' as value to 'allowed_origins' under 'cors' block which exists under 'site_config' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#allowed_origins' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_WEB_006.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Ensure CORS configuration is not allowing every resources to access Azure App Service

***<font color="white">Description:</font>*** This policy will identify CORS configuration which are allowing every resoruces to access Azure app service and give alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_app_service']


[appservice.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/appservice.rego
