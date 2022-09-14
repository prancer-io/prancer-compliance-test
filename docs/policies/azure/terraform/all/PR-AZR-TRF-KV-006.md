



# Master Test ID: PR-AZR-TRF-KV-006


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(KeyVault.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-KV-006|
|eval: |data.rule.kv_public_network_access_disabled|
|message: |data.rule.kv_public_network_access_disabled_err|
|remediationDescription: |In 'azurerm_key_vault' resource, set default_action = 'Deny' under 'network_acls' block to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#default_action' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_KV_006.py|


severity: Medium

title: Azure Key Vault Network Access default action should be 'deny'

description: Disable public network access for your key vault so that it's not accessible over the public internet. This can reduce data leakage risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_key_vault']


[file(KeyVault.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego
