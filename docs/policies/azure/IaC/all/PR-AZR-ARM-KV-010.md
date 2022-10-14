



# Title: Azure KeyVault Public Network Access should be 'disabled'


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-KV-010

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([KeyVault.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-KV-010|
|eval|data.rule.kv_public_access_disabled|
|message|data.rule.kv_public_access_disabled_err|
|remediationDescription|In Resource of type "Microsoft.KeyVault/vaults" make sure 'properties.publicNetworkAccess' exists and the value is set 'disabled'.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults?tabs=json' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_KV_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure KeyVault Public Network Access should be 'disabled' so that it's not accessible over the public internet. This can reduce data leakage risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.keyvault/vaults']


[KeyVault.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego
