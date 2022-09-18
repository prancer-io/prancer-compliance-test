



# Title: Ensure 'default' value is not used on Security Group setting for Redis cache engines


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-EC-006

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-EC-006|
|eval|data.rule.cache_default_sg|
|message|data.rule.cache_default_sg_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-cachesubnetgroupname' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_EC_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure 'default' value is not used on Security Group setting for Redis cache engines  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::elasticache::replicationgroup']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego
