



# Title: Azure Key Vault Trusted Microsoft Services access should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-KV-007

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([KeyVault.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-KV-007|
|eval|data.rule.keyvault_bypass|
|message|data.rule.keyvault_bypass_err|
|remediationDescription|In Resource of type "Microsoft.KeyVault/vaults" make sure properties.networkAcls.bypass exists and the value isn't set 'AzureServices'.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults?tabs=json' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_KV_007.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.keyvault/vaults']


[KeyVault.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego
