



# Title: Azure Key Vault Network Access default action should be 'deny'


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-KV-006

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([KeyVault.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-KV-006|
|eval|data.rule.keyvault_Acl|
|message|data.rule.keyvault_Acl_err|
|remediationDescription|In Resource of type "Microsoft.KeyVault/vaults" make sure properties.networkAcls.defaultAction exists and the value isn't set 'deny'.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults?tabs=json' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_KV_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.keyvault/vaults']


[KeyVault.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego
