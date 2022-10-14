



# Title: Key Vault should use a virtual network service endpoint


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-KV-008

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([KeyVault.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-KV-008|
|eval|data.rule.keyvault_service_endpoint|
|message|data.rule.keyvault_service_endpoint_err|
|remediationDescription|In Resource of type "Microsoft.KeyVault/vaults" make sure properties.networkAcls.virtualNetworkRules.ignoreMissingVnetServiceEndpoint isn't set false.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults?tabs=json' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_KV_008.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy audits any Key Vault not configured to use a virtual network service endpoint.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.keyvault/vaults']


[KeyVault.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego
