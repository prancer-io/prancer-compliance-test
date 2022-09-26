



# Title: Storage accounts should use private link


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-STR-019

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_301', 'AZRSNP_500']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-STR-019|
|eval|data.rule.storage_account_private_endpoint|
|message|data.rule.storage_account_private_endpoint_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/storage/common/storage-private-endpoints' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_STR_019.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Azure Private Link lets you connect your virtual network to Azure services without a public IP address at the source or destination. The Private Link platform handles the connectivity between the consumer and services over the Azure backbone network. By mapping private endpoints to your storage account, data leakage risks are reduced. Learn more about private links at - https://aka.ms/azureprivatelinkoverview  
  
  

|Title|Description|
| :---: | :---: |
|cloud|Azure|
|compliance|['Best Practice']|
|service|['Storage']|



[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/storageaccounts.rego
