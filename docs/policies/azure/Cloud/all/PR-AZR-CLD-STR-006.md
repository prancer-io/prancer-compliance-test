



# Title: Ensure that 'Storage service encryption' is enabled for the Blob Service


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-STR-006

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_301']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-STR-006|
|eval|data.rule.blobService|
|message|data.rule.blobService_err|
|remediationDescription|Currently, Storage account supports customer-managed keys encryption for blobs by default upon account creation, this cannot be changed after.<br>Note: When customer-managed keys are configured, your data in Blob storage and Azure Files is automatically protected using the customer-managed keys.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_CLD_STR_006.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Enable data encryption at rest for blobs. Storage service encryption protects your data at rest. Azure Storage encrypts data when it's written, and automatically decrypts it when it is accessed.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|Azure|
|compliance|['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['Storage']|



[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/storageaccounts.rego
