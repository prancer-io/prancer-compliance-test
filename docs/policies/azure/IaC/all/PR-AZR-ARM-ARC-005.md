



# Title: Configure Azure Cache for redis with private endpoints


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-ARC-005

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Redis.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-ARC-005|
|eval|data.rule.arc_private_endpoint|
|message|data.rule.arc_private_endpoint_err|
|remediationDescription|In Resource of type "Microsoft.Cache/redis" make sure 'Microsoft.Network/privateEndpoints' exists.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults?tabs=json' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_ARC_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure Private Link lets you connect your virtual network to Azure services without a public IP address at the source or destination. The Private Link platform handles the connectivity between the consumer and services over the Azure backbone network. By mapping private endpoints to your cache for redis, data leakage risks are reduced. Learn more about private links at - https://aka.ms/azureprivatelinkoverview  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.cache/redis/linkedservers', 'microsoft.cache/redis']


[Redis.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/Redis.rego
