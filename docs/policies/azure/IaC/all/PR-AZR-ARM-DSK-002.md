



# Title: Enable server-side encryption with customer-managed keys for managed disks


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-DSK-002

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([disks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-DSK-002|
|eval|data.rule.disk_encryption_2|
|message|data.rule.disk_encryption_2_err|
|remediationDescription|Make sure you are following the ARM template guidelines for Disks by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/disks' target='_blank'>here</a>. encryption.diskEncryptionSetId should be exists and encryption.type should be exists and the value = 'EncryptionATrestWithCustomerkey'|
|remediationFunction|PR_AZR_ARM_DSK_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Azure Disk Storage allows you to manage your own keys when using server-side encryption (SSE) for managed disks, if you choose  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.compute/disks']


[disks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/disks.rego
