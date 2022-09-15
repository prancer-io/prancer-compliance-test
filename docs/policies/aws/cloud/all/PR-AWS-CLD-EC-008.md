



# Master Test ID: PR-AWS-CLD-EC-008


***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EC-008|
|eval|data.rule.redis_with_intransit_encryption|
|message|data.rule.redis_with_intransit_encryption_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elasticache.html#ElastiCache.Client.describe_cache_clusters' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EC_008.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure ElastiCache Redis with in-transit encryption is disabled (Non-replication group).

***<font color="white">Description:</font>*** It identifies ElastiCache Redis that are in non-replication groups or individual ElastiCache Redis and have in-transit encryption disabled. It is highly recommended to implement in-transit encryption in order to protect data from unauthorized access as it travels through the network, between clients and cache servers. Enabling data encryption in-transit helps prevent unauthorized users from reading sensitive data between your Redis and their associated cache storage systems.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['elasticache']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
