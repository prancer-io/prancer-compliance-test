



# Title: Ensure that 'Storage service encryption' is enabled for the File Service


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-STR-007

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-STR-007|
|eval|data.rule.fileService|
|message|data.rule.fileService_err|
|remediationDescription|In Resource of type "Microsoft.storage/storageaccounts" make sure properties.encryption.services.file exists and file.enabled is set to true.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_STR_007.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Azure Storage encryption protects your data and helps you to meet your organizational security and compliance commitments. Data in Azure Storage is encrypted and decrypted transparently using 256-bit AES encryption, one of the strongest block ciphers available, and is FIPS 140-2 compliant. Azure Storage encryption is similar to BitLocker encryption on Windows.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'GDPR', 'ISO 27001', 'HIPAA', 'Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.storage/storageaccounts']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/storageaccounts.rego
