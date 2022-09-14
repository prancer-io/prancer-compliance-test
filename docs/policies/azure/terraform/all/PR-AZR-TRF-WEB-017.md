



# Master Test ID: PR-AZR-TRF-WEB-017


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(appservice.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-WEB-017|
|eval: |data.rule.app_service_storage_account_type_azurefile|
|message: |data.rule.app_service_storage_account_type_azurefile_err|
|remediationDescription: |In 'azurerm_app_service' resource, set type = 'AzureFiles' under 'storage_account' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#storage_account' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_WEB_017.py|


severity: Medium

title: Azure App Service storage account type should be AzureFiles

description: This policy will identify the Azure app service which dont have storage account type AzureFiles and give alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |[]|
|service: |['terraform']|


resourceTypes: ['azurerm_app_service']


[file(appservice.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/appservice.rego
