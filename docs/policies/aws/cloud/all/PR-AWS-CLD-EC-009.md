



# Master Test ID: PR-AWS-CLD-EC-009


Master Snapshot Id: ['TEST_EC']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-EC-009|
|eval: |data.rule.cache_replication_group_id|
|message: |data.rule.cache_replication_group_id_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elasticache.html#ElastiCache.Client.describe_replication_groups' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_EC_009.py|


severity: Medium

title: Ensure ElastiCache (Redis) replicationGroupId is not empty or contains wildcards (*).

description: This checks if the replication group ID for Redis is set to empty or a * to allow all.This checks if the replication group ID for Redis is set to empty or a * to allow all.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['elasticache']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
