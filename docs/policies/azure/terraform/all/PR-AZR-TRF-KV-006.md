



# Title: Azure Key Vault Network Access default action should be 'deny'


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-KV-006

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([KeyVault.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-KV-006|
|eval|data.rule.kv_public_network_access_disabled|
|message|data.rule.kv_public_network_access_disabled_err|
|remediationDescription|In 'azurerm_key_vault' resource, set default_action = 'Deny' under 'network_acls' block to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#default_action' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_KV_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Disable public network access for your key vault so that it's not accessible over the public internet. This can reduce data leakage risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_key_vault']


[KeyVault.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego
