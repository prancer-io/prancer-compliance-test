



# Master Test ID: PR-AZR-TRF-WEB-013


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(appservice.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-WEB-013|
|eval: |data.rule.app_service_dot_net_framework_latest|
|message: |data.rule.app_service_dot_net_framework_latest_err|
|remediationDescription: |In 'azurerm_app_service' resource, set dotnet_framework_version = 'v6.0' under 'site_config' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#dotnet_framework_version' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_WEB_013.py|


severity: Medium

title: Azure App Service Dot Net Framework should be latest

description: This policy will identify the Azure app service which dont have latest version of Dot Net Framework and give alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |[]|
|service: |['terraform']|


resourceTypes: ['azurerm_app_service']


[file(appservice.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/appservice.rego
