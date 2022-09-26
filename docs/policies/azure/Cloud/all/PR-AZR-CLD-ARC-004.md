



# Title: Azure Cache for Redis should reside within a virtual network


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-ARC-004

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_420']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Redis.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-ARC-004|
|eval|data.rule.arc_subnet_id|
|message|data.rule.arc_subnet_id_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/azure-cache-for-redis/cache-how-to-premium-vnet' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_ARC_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure Virtual Network deployment provides enhanced security and isolation for your Azure Cache for Redis, as well as subnets, access control policies, and other features to further restrict access.When an Azure Cache for Redis instance is configured with a virtual network, it is not publicly addressable and can only be accessed from virtual machines and applications within the virtual network.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Databases']|



[Redis.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/Redis.rego
