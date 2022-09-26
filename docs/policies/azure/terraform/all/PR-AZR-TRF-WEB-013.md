



# Title: Azure App Service Dot Net Framework should be latest


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-WEB-013

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([appservice.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-WEB-013|
|eval|data.rule.app_service_dot_net_framework_latest|
|message|data.rule.app_service_dot_net_framework_latest_err|
|remediationDescription|In 'azurerm_app_service' resource, set dotnet_framework_version = 'v6.0' under 'site_config' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#dotnet_framework_version' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_WEB_013.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy will identify the Azure app service which dont have latest version of Dot Net Framework and give alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_app_service']


[appservice.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/appservice.rego
