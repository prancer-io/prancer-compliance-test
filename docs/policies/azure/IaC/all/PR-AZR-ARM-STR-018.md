



# Title: Ensure Azure Storage Account has latest version of tls configured


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-STR-018

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-STR-018|
|eval|data.rule.storage_account_latest_tls_configured|
|message|data.rule.storage_account_latest_tls_configured_err|
|remediationDescription|In 'microsoft.storage/storageaccounts' resource, set minimumTlsVersion = 'TLS1_2' to fix the issue.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_STR_018.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy will identify the Azure Storage Account which don't have the latest version of tls configured and give the alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CIS v1.4.0 (Azure)-3.12']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.storage/storageaccounts']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/storageaccounts.rego
