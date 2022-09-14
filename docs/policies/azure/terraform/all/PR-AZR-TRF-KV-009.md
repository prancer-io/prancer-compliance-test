



# Master Test ID: PR-AZR-TRF-KV-009


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(KeyVault.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-KV-009|
|eval: |data.rule.kv_usage_private_enpoint|
|message: |data.rule.kv_usage_private_enpoint_err|
|remediationDescription: |'azurerm_key_vault' resource need to have a link with 'azurerm_private_endpoint', set 'id' of 'azurerm_key_vault' to property 'private_connection_resource_id' under 'azurerm_private_endpoint' resources 'private_service_connection' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint#private_connection_resource_id' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_KV_009.py|


severity: Medium

title: Azure KeyVault should use private link

description: Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure KeyVault, data leakage risks are reduced.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_key_vault', 'azurerm_private_endpoint']


[file(KeyVault.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego
