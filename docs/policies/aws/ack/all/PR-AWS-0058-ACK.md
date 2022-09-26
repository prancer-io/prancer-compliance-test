



# Title: AWS ElastiCache Redis cluster with in-transit encryption disabled


***<font color="white">Master Test Id:</font>*** TEST_ELASTIC_CACHE_4

***<font color="white">Master Snapshot Id:</font>*** ['ACK_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elasticache.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-0058-ACK|
|eval|data.rule.cache_encrypt|
|message|data.rule.cache_encrypt_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies ElastiCache Redis clusters which have in-transit encryption disabled. It is highly recommended to implement in-transit encryption in order to protect data from unauthorized access as it travels through the network, between clients and cache servers. Enabling data encryption in-transit helps prevent unauthorized users from reading sensitive data between your Redis clusters and their associated cache storage systems.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['ack']|



[elasticache.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/ack/elasticache.rego
