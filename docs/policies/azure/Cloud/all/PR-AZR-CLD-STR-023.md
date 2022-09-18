



# Title: Storage Accounts should use a virtual network service endpoint


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-STR-023

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_301']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-STR-023|
|eval|data.rule.storage_vnet_service_endpoint|
|message|data.rule.storage_vnet_service_endpoint_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-service-endpoint-policies-overviewv' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_STR_023.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy audits any Storage Account not configured to use a virtual network service endpoint.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|Azure|
|compliance|['Best Practice']|
|service|['Storage']|



[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/storageaccounts.rego
