



# Master Test ID: PR-AZR-TRF-STR-018


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-STR-018|
|eval|data.rule.storage_account_latest_tls_configured|
|message|data.rule.storage_account_latest_tls_configured_err|
|remediationDescription|In 'azurerm_storage_account' resource, set min_tls_version = 'TLS1_2' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#min_tls_version' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_STR_018.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure Azure Storage Account has latest version of tls configured

***<font color="white">Description:</font>*** This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CIS v1.4.0 (Azure)-3.12']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_storage_account']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego
