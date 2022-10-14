



# Title: Redis cache should have a backup


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-ARC-002

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_420']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Redis.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-ARC-002|
|eval|data.rule.serverRole|
|message|data.rule.serverRole_err|
|remediationDescription|In Azure Portal:<br>1. Go to Redis Caches.<br>2. For each Redis Cache:<br>3. Make sure you have at least 2 Redis Caches in Premium tier.<br>4. Click on Geo-replication<br>5. Click Add cache replication link<br>6. Click the name of the desired secondary cache from the Compatible caches list.<br>7. Click the 3 dots on the right to open the context menu.<br>8. Select Link as secondary.<br>8. Select Link.<br><br>Default Value:<br>No linked<br><br>References:<br><a href='https://docs.microsoft.com/en-us/azure/redis-cache/cache-how-to-geo-replication' target='_blank'>https://docs.microsoft.com/en-us/azure/redis-cache/cache-how-to-geo-replication</a>|
|remediationFunction|PR_AZR_CLD_ARC_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Replicate Redis Cache server data to another Redis Cache server using geo replication. This feature is only available for Premium tier Redis Cache. From performance point of view, Microsoft recommends that both Redis Caches (Primary and the linked secondary) reside in the same region.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice']|
|service|['Databases']|



[Redis.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/Redis.rego
