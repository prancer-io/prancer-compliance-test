



# Title: Azure Key Vault Network Access default action should be 'deny'


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-KV-006

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_228']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Keyvault.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-KV-006|
|eval|data.rule.keyvault_Acl|
|message|data.rule.keyvault_Acl_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/bs-latn-ba/azure/key-vault/general/how-to-azure-key-vault-network-security?tabs=azure-portal' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_KV_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|[]|
|service|['Security']|



[Keyvault.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/Keyvault.rego
