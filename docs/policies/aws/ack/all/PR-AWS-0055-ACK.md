



# Title: AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled


***<font color="white">Master Test Id:</font>*** TEST_ELASTIC_CACHE_1

***<font color="white">Master Snapshot Id:</font>*** ['ACK_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elasticache.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-0055-ACK|
|eval|data.rule.cache_failover|
|message|data.rule.cache_failover_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies ElastiCache Redis clusters which have Multi-AZ Automatic Failover feature set to disabled. It is recommended to enable the Multi-AZ Automatic Failover feature for your Redis Cache cluster, which will improve primary node reachability by providing read replica in case of network connectivity loss or loss of availability in the primary's availability zone for read/write operations.<br>Note: Redis cluster Multi-AZ with automatic failover does not support T1 and T2 cache node types and is only available if the cluster has at least one read replica.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['ack']|



[elasticache.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/ack/elasticache.rego
