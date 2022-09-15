



# Master Test ID: PR-AZR-TRF-KV-008


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([KeyVault.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-KV-008|
|eval|data.rule.kv_service_endpoint_enabled|
|message|data.rule.kv_service_endpoint_enabled_err|
|remediationDescription|In 'azurerm_key_vault' resource, add source subnet ids into 'virtual_network_subnet_ids' array property under 'network_acls' block to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#virtual_network_subnet_ids' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_KV_008.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Azure KeyVault should allow access from virtual network service endpoint

***<font color="white">Description:</font>*** This policy will identify if One or more Subnet ID's have access to this Key Vault. Will warn if not found.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_key_vault']


[KeyVault.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego
