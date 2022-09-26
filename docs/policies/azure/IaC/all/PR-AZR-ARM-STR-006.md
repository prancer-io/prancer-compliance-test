



# Title: Ensure that 'Storage service encryption' is enabled for the Blob Service


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-STR-006

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-STR-006|
|eval|data.rule.blobService|
|message|data.rule.blobService_err|
|remediationDescription|In Resource of type "Microsoft.storage/storageaccounts" make sure properties.encryption.services.blob exists and blob.enabled is set to true.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_STR_006.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Enable data encryption at rest for blobs. Storage service encryption protects your data at rest. Azure Storage encrypts data when it's written, and automatically decrypts it when it is accessed.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.storage/storageaccounts']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/storageaccounts.rego
