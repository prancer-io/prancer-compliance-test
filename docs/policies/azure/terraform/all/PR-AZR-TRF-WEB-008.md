



# Master Test ID: PR-AZR-TRF-WEB-008


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(appservice.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-WEB-008|
|eval: |data.rule.app_service_detaild_error_message_enabled|
|message: |data.rule.app_service_detaild_error_message_enabled_err|
|remediationDescription: |In 'azurerm_app_service' resource, set 'detailed_error_messages_enabled = true' under 'logs' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#detailed_error_messages_enabled' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_WEB_008.py|


severity: Medium

title: Azure App Service detaild error message should be enabled

description: This policy will identify the Azure app service which dont have detaild error message enabled and give alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |[]|
|service: |['terraform']|


resourceTypes: ['azurerm_app_service']


[file(appservice.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/appservice.rego
