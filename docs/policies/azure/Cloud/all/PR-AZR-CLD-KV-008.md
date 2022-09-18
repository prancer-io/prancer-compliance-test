



# Title: Key Vault should use a virtual network service endpoint


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-KV-008

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_228']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Keyvault.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-KV-008|
|eval|data.rule.keyvault_service_endpoint|
|message|data.rule.keyvault_service_endpoint_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/key-vault/general/overview-vnet-service-endpoints' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_KV_008.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy audits any Key Vault not configured to use a virtual network service endpoint.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|[]|
|service|['Security']|



[Keyvault.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/Keyvault.rego
