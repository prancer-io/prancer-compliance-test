



# Title: Ensure that ElastiCache replication Group (Redis) are encrypted at rest with customer managed CMK key


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-EC-005

***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EC-005|
|eval|data.rule.cache_ksm_key|
|message|data.rule.cache_ksm_key_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-kmskeyid' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EC_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies ElastiCache Redis clusters which have in-transit encryption disabled. It is highly recommended to implement in-transit encryption in order to protect data from unauthorized access as it travels through the network, between clients and cache servers. Enabling data encryption in-transit helps prevent unauthorized users from reading sensitive data between your Redis clusters and their associated cache storage systems.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['MAS TRM', 'MAS TRM 2021-11.1.1', 'MAS TRM 2021-11.1.3', 'RMiT', 'Risk Management in Technology (RMiT)-10.51', 'Risk Management in Technology (RMiT)-10.68']|
|service|['elasticache']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
