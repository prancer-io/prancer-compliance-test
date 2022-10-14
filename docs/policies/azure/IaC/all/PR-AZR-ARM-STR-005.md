



# Title: Advanced Threat Protection should be enabled for storage account


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-STR-005

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-STR-005|
|eval|data.rule.storage_threat_protection|
|message|data.rule.storage_threat_protection_err|
|remediationDescription|Make sure you are following the ARM template guidelines for storage accounts by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts' target='_blank'>here</a>. Also visit <a href='https://github.com/Azure/azure-quickstart-templates/blob/master/quickstarts/microsoft.storage/storage-advanced-threat-protection-create/azuredeploy.json' target='_blank'>here</a> for template reference|
|remediationFunction|PR_AZR_ARM_STR_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Advanced Threat Protection should be enabled for all the storage accounts  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.storage/storageaccounts']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/storageaccounts.rego
