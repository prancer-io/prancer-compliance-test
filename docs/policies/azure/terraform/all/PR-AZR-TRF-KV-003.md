



# Master Test ID: PR-AZR-TRF-KV-003


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([KeyVault.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-KV-003|
|eval|data.rule.enablePurgeProtection|
|message|data.rule.enablePurgeProtection_err|
|remediationDescription|In 'azurerm_key_vault' resource, set 'purge_protection_enabled = true' to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#purge_protection_enabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_KV_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Key vault should have purge protection enabled

***<font color="white">Description:</font>*** The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1485 - Data Destruction']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_key_vault']


[KeyVault.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego
