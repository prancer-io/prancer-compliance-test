



# Title: Ensure at least one principal has access to Keyvault


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-KV-001

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([KeyVault.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-KV-001|
|eval|data.rule.KeyVault|
|message|data.rule.KeyVault_err|
|remediationDescription|In Resource of type "Microsoft.KeyVault/vaults" make sure you have added either permissions.keys or permissions.secrets or permissions.certificates under each AccessPolicyEntry of properties.accessPolicies.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults?tabs=json' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_KV_001.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice', 'HIPAA', 'NIST CSF']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.keyvault/vaults']


[KeyVault.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego
