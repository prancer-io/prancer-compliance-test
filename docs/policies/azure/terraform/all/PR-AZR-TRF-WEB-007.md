



# Master Test ID: PR-AZR-TRF-WEB-007


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(appservice.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-WEB-007|
|eval: |data.rule.app_service_http_logging_enabled|
|message: |data.rule.app_service_http_logging_enabled_err|
|remediationDescription: |In 'azurerm_app_service' resource, make sure 'http_logs' block exist under 'logs' block to fix the issue. Visit https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#http_logs for details.|
|remediationFunction: |PR_AZR_TRF_WEB_007.py|


severity: Medium

title: Azure App Service http logging should be enabled

description: This policy will identify the Azure app service which dont have http logging enabled and give alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |[]|
|service: |['terraform']|


resourceTypes: ['azurerm_app_service']


[file(appservice.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/appservice.rego
