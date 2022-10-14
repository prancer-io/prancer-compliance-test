



# Title: Azure Key Vault Trusted Microsoft Services access should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-KV-007

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_228']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Keyvault.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-KV-007|
|eval|data.rule.keyvault_bypass|
|message|data.rule.keyvault_bypass_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/key-vault/general/network-security' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_KV_007.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|[]|
|service|['Security']|



[Keyvault.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/Keyvault.rego
