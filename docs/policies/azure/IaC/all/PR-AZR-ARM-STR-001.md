



# Title: Soft delete on blob service should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-STR-001

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-STR-001|
|eval|data.rule.storage_blob_soft_delete|
|message|data.rule.storage_blob_soft_delete_err|
|remediationDescription|For resource type "Microsoft.storage/storageaccounts/blobservices" make sure properties.deleteRetentionPolicy.enabled exists and value is set to true .<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/blobservices' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_STR_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The blob service properties for blob soft delete. It helps to restore removed blob within configured retention days  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITTRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.storage/storageaccounts', 'microsoft.storage/storageaccounts/blobservices']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/storageaccounts.rego
