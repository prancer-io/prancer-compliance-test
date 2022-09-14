



# Master Test ID: PR-AWS-CLD-EC-007


Master Snapshot Id: ['TEST_EC_01']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-EC-007|
|eval: |data.rule.automatic_backups_for_redis_cluster|
|message: |data.rule.automatic_backups_for_redis_cluster_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elasticache.html#ElastiCache.Client.describe_cache_clusters' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_EC_007.py|


severity: Medium

title: Ensure in AWS ElastiCache, automatic backups is enabled for Redis cluster.

description: It checks if automatic backups are enabled for the Redis cluster.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'CCPA', 'HITRUST', 'LGPD', 'MAS TRM', 'PCI-DSS', 'NIST 800', 'NIST SP']|
|service: |['elasticache']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
