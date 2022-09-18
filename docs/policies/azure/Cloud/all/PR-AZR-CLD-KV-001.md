



# Title: Ensure at least one principal has access to Keyvault


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-KV-001

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_228']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Keyvault.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-KV-001|
|eval|data.rule.KeyVault|
|message|data.rule.KeyVault_err|
|remediationDescription|1. Go to 'Key vaults' and choose your Key Vault<br>2. Select 'Keys/Secrets/Certificates' under 'Settings' in the navigation menu<br>3. Select 'Generate/Import' and complete the wizard.<br>Please visit <a href='https://docs.microsoft.com/en-us/cli/azure/keyvault?view=azure-cli-latest' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_CLD_KV_001.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice', 'HIPAA', 'NIST CSF']|
|service|['Security']|



[Keyvault.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/Keyvault.rego
