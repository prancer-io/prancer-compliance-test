



# Title: Ensure in AWS ElastiCache, automatic backups is enabled for Redis cluster.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-EC-007

***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EC-007|
|eval|data.rule.automatic_backups_for_redis_cluster|
|message|data.rule.automatic_backups_for_redis_cluster_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elasticache.html#ElastiCache.Client.describe_cache_clusters' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EC_007.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks if automatic backups are enabled for the Redis cluster.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'CCPA', 'HITRUST', 'LGPD', 'MAS TRM', 'PCI-DSS', 'NIST 800', 'NIST SP']|
|service|['elasticache']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
