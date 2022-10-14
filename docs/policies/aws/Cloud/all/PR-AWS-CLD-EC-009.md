



# Title: Ensure ElastiCache (Redis) replicationGroupId is not empty or contains wildcards (*).


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-EC-009

***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EC-009|
|eval|data.rule.cache_replication_group_id|
|message|data.rule.cache_replication_group_id_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elasticache.html#ElastiCache.Client.describe_replication_groups' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EC_009.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This checks if the replication group ID for Redis is set to empty or a * to allow all.This checks if the replication group ID for Redis is set to empty or a * to allow all.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['elasticache']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
