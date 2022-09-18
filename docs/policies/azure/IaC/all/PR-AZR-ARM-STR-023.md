



# Title: Storage Accounts should use a virtual network service endpoint


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-STR-023

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-STR-023|
|eval|data.rule.storage_vnet_service_endpoint|
|message|data.rule.storage_vnet_service_endpoint_err|
|remediationDescription|In 'microsoft.storage/storageaccounts' resource, set networkAcls.defaultAction = 'deny' and networkAcls.virtualNetworkRules.id should to be exists to fix the issue.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/encryptionscopes' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_STR_023.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy audits any Storage Account not configured to use a virtual network service endpoint.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.storage/storageaccounts']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/storageaccounts.rego
