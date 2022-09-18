



# Title: Azure Key Vault Trusted Microsoft Services access should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-KV-007

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([KeyVault.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-KV-007|
|eval|data.rule.kv_allow_bypass_for_azure_services|
|message|data.rule.kv_allow_bypass_for_azure_services_err|
|remediationDescription|In 'azurerm_key_vault' resource, set bypass = 'AzureServices' under 'network_acls' block to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#bypass' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_KV_007.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** When you enable the Key Vault Firewall, you will be given an option to 'Allow Trusted Microsoft Services to bypass this firewall'. The trusted services list encompasses services where Microsoft controls all of the code that runs on the service.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_key_vault']


[KeyVault.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego
