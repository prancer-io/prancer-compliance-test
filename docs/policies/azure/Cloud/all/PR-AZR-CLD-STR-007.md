



# Title: Ensure that 'Storage service encryption' is enabled for the File Service


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-STR-007

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_301']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-STR-007|
|eval|data.rule.fileService|
|message|data.rule.fileService_err|
|remediationDescription|By default Azure Storage uses server-side encryption (SSE) to automatically encrypt your data when it is persisted to the cloud.<br>No autoremediation needed.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_CLD_STR_007.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Azure Storage encryption protects your data and helps you to meet your organizational security and compliance commitments. Data in Azure Storage is encrypted and decrypted transparently using 256-bit AES encryption, one of the strongest block ciphers available, and is FIPS 140-2 compliant. Azure Storage encryption is similar to BitLocker encryption on Windows  
  
  

|Title|Description|
| :---: | :---: |
|cloud|Azure|
|compliance|['PCI-DSS', 'GDPR', 'ISO 27001', 'HIPAA', 'Best Practice']|
|service|['Storage']|



[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/storageaccounts.rego
