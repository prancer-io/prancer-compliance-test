



# Title: Azure KeyVault Public Network Access should be 'disabled'


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-KV-010

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_228']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Keyvault.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-KV-010|
|eval|data.rule.kv_public_access_disabled|
|message|data.rule.kv_public_access_disabled_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/key-vault/general/network-security' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_KV_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure KeyVault Public Network Access should be 'disabled' so that it's not accessible over the public internet. This can reduce data leakage risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|[]|
|service|['Security']|



[Keyvault.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/Keyvault.rego
