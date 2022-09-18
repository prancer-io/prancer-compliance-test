



# Title: AWS ElastiCache Redis cluster with encryption for data at rest disabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-EC-003

***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EC-003|
|eval|data.rule.cache_redis_encrypt|
|message|data.rule.cache_redis_encrypt_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EC_003.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy identifies ElastiCache Redis clusters which have encryption for data at rest(at-rest) is disabled. It is highly recommended to implement at-rest encryption in order to prevent unauthorized users from reading sensitive data saved to persistent media available on your Redis clusters and their associated cache storage systems.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['HIPAA', 'GDPR', 'NIST 800']|
|service|['elasticache']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
