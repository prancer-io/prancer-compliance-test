



# Title: Ensure Azure Storage Account has latest version of tls configured


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-STR-018

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_301']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-STR-018|
|eval|data.rule.storage_account_latest_tls_configured|
|message|data.rule.storage_account_latest_tls_configured_err|
|remediationDescription|To configure the minimum TLS version for an existing storage account with the Azure portal, follow these steps:<br><br>1. Navigate to your storage account in the Azure portal.<br>2. Under Settings, select Configuration.<br>3. Under Minimum TLS version, use the drop-down to select the minimum version of TLS required to access data in this storage account|
|remediationFunction|PR_AZR_CLD_STR_018.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy will identify the Azure Storage Account which don't have the latest version of tls configured and give the alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|Azure|
|compliance|['CIS', 'CIS v1.4.0 (Azure)-3.12']|
|service|['Storage']|



[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/storageaccounts.rego
