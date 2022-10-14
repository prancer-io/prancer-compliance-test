



# Title: Storage accounts should use private link


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-STR-019

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-STR-019|
|eval|data.rule.storage_account_private_endpoint|
|message|data.rule.storage_account_private_endpoint_err|
|remediationDescription|In 'microsoft.storage/storageaccounts' resource, make sure 'microsoft.network/privateendpoints' resource exists and connects to 'Microsoft.storage/storageAccounts'.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_STR_019.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Azure Private Link lets you connect your virtual network to Azure services without a public IP address at the source or destination. The Private Link platform handles the connectivity between the consumer and services over the Azure backbone network. By mapping private endpoints to your storage account, data leakage risks are reduced. Learn more about private links at - https://aka.ms/azureprivatelinkoverview  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.storage/storageaccounts']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/storageaccounts.rego
