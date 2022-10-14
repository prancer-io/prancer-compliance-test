



# Title: Key vault should have purge protection enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-KV-003

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_228']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Keyvault.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-KV-003|
|eval|data.rule.enablePurgeProtection|
|message|data.rule.enablePurgeProtection_err|
|remediationDescription|Via Azure Portal<br>Azure Portal does not have provision to update the respective configurations<br><br>Via Azure CLI<br>Existing key vault:<br><br>For an existing key vault named ContosoVault, enable purge-protection as follows:<br><br>az resource update --ids $(az keyvault show --name ContosoVault -o tsv , awk '{print $1}') --set properties.enablePurgeProtection=true.<br>Please visit <a href='https://docs.microsoft.com/en-us/cli/azure/keyvault?view=azure-cli-latest' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_CLD_KV_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1485 - Data Destruction']|
|service|['Security']|



[Keyvault.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/Keyvault.rego
