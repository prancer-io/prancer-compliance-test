



# Title: Azure App Service Failed request tracing should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-WEB-009

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([appservice.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-WEB-009|
|eval|data.rule.app_service_failed_request_tracing_enabled|
|message|data.rule.app_service_failed_request_tracing_enabled_err|
|remediationDescription|In 'azurerm_app_service' resource, set 'app_service_failed_request_tracing_enabled = true' under 'logs' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#failed_request_tracing_enabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_WEB_009.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy will identify the Azure app service which dont have Failed request tracing enabled and give alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_app_service']


[appservice.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/appservice.rego
