



# Title: Enable server-side encryption with customer-managed keys for managed disks


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-DSK-002

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_277']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([disks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-DSK-002|
|eval|data.rule.disk_encryption_2|
|message|data.rule.disk_encryption_2_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/virtual-machines/disks-enable-customer-managed-keys-portal' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_DSK_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Azure Disk Storage allows you to manage your own keys when using server-side encryption (SSE) for managed disks, if you choose  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Compute']|



[disks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/disks.rego
