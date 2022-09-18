



# Title: Key vault should have purge protection enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-KV-003

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([KeyVault.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-KV-003|
|eval|data.rule.enablePurgeProtection|
|message|data.rule.enablePurgeProtection_err|
|remediationDescription|In Resource of type "Microsoft.KeyVault/vaults" make sure properties.enablePurgeProtection exists and value is set to true.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults?tabs=json' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_KV_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1485 - Data Destruction']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.keyvault/vaults']


[KeyVault.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego
