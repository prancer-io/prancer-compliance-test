



# Master Test ID: PR-AZR-TRF-STR-017


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-STR-017|
|eval|data.rule.storage_correct_naming_convention|
|message|data.rule.storage_correct_naming_convention_err|
|remediationDescription|In 'azurerm_storage_account' resource, property 'name' must be between 3 and 24 characters in length and may contain numbers and lowercase letters only to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#name' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_STR_017.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure Storage Account naming rules are correct

***<font color="white">Description:</font>*** Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_storage_account']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego
