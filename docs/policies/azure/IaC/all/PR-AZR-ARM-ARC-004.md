



# Title: Azure Cache for Redis should reside within a virtual network


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-ARC-004

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Redis.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-ARC-004|
|eval|data.rule.arc_subnet_id|
|message|data.rule.arc_subnet_id_err|
|remediationDescription|In Resource of type 'Microsoft.Cache/redis' make sure properties.subnetId exists and connected to Azure Redis.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_ARC_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure Virtual Network deployment provides enhanced security and isolation for your Azure Cache for Redis, as well as subnets, access control policies, and other features to further restrict access.When an Azure Cache for Redis instance is configured with a virtual network, it is not publicly addressable and can only be accessed from virtual machines and applications within the virtual network.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.cache/redis/linkedservers', 'microsoft.cache/redis']


[Redis.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/Redis.rego
