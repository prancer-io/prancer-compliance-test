



# Title: AWS ElastiCache Redis cluster with Redis AUTH feature disabled


***<font color="white">Master Test Id:</font>*** TEST_ELASTIC_CACHE_2

***<font color="white">Master Snapshot Id:</font>*** ['ACK_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elasticache.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-0056-ACK|
|eval|data.rule.cache_redis_auth|
|message|data.rule.cache_redis_auth_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies ElastiCache Redis clusters which have Redis AUTH feature disabled. Redis AUTH can improve data security by requiring the user to enter a password before they are granted permission to execute Redis commands on a password protected Redis server.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['ack']|



[elasticache.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/ack/elasticache.rego
