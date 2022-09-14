



# Master Test ID: PR-AZR-TRF-KV-007


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(KeyVault.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-KV-007|
|eval: |data.rule.kv_allow_bypass_for_azure_services|
|message: |data.rule.kv_allow_bypass_for_azure_services_err|
|remediationDescription: |In 'azurerm_key_vault' resource, set bypass = 'AzureServices' under 'network_acls' block to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#bypass' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_KV_007.py|


severity: High

title: Azure Key Vault Trusted Microsoft Services access should be enabled

description: When you enable the Key Vault Firewall, you will be given an option to 'Allow Trusted Microsoft Services to bypass this firewall'. The trusted services list encompasses services where Microsoft controls all of the code that runs on the service.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_key_vault']


[file(KeyVault.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego
