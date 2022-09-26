



# Title: Soft delete on blob service should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-STR-001

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_301']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-STR-001|
|eval|data.rule.storage_blob_soft_delete|
|message|data.rule.storage_blob_soft_delete_err|
|remediationDescription|To enable blob soft delete for your storage account by using the Azure portal, follow these steps:<br><br>1. In the Azure portal, navigate to your storage account.<br>2. Locate the Data Protection option under Blob service.<br>3. In the Recovery section, select Turn on soft delete for blobs.<br>4. Specify a retention period between 1 and 365 days. Microsoft recommends a minimum retention period of seven days.<br>5. Save your changes.|
|remediationFunction|PR_AZR_CLD_STR_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The blob service properties for blob soft delete. It helps to restore removed blob within configured retention days  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['CIS', 'CSA-CCM', 'HITTRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['Storage']|



[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/storageaccounts.rego
