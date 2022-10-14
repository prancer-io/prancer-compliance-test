



# Title: AWS ElastiCache Redis cluster with encryption for data at rest disabled


***<font color="white">Master Test Id:</font>*** TEST_ELASTIC_CACHE_3

***<font color="white">Master Snapshot Id:</font>*** ['ACK_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elasticache.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-0057-ACK|
|eval|data.rule.cache_redis_encrypt|
|message|data.rule.cache_redis_encrypt_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies ElastiCache Redis clusters which have encryption for data at rest(at-rest) is disabled. It is highly recommended to implement at-rest encryption in order to prevent unauthorized users from reading sensitive data saved to persistent media available on your Redis clusters and their associated cache storage systems.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['ack']|



[elasticache.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/ack/elasticache.rego
