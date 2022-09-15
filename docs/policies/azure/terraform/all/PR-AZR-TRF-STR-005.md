



# Master Test ID: PR-AZR-TRF-STR-005


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-STR-005|
|eval|data.rule.storage_threat_protection|
|message|data.rule.storage_threat_protection_err|
|remediationDescription|In 'azurerm_advanced_threat_protection' resource, set 'enabled = true' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/advanced_threat_protection#enabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_STR_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Advanced Threat Protection should be enabled for storage account

***<font color="white">Description:</font>*** Advanced Threat Protection should be enabled for all the storage accounts  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_advanced_threat_protection', 'azurerm_storage_account']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego
