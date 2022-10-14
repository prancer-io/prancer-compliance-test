



# Title: Redis cache should have a backup


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-ARC-002

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Redis.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-ARC-002|
|eval|data.rule.serverRole|
|message|data.rule.serverRole_err|
|remediationDescription|In Resource of type "Microsoft.Cache/redis/linkedServers" make sure properties.serverRole value is set to Secondary.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis/linkedservers' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_ARC_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Replicate Redis Cache server data to another Redis Cache server using geo replication. This feature is only available for Premium tier Redis Cache. From performance point of view, Microsoft recommends that both Redis Caches (Primary and the linked secondary) reside in the same region.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.cache/redis/linkedservers', 'microsoft.cache/redis']


[Redis.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/Redis.rego
