



# Title: Ensure respective logs of Amazon RDS instance are enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-RDS-018

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-RDS-018|
|eval|data.rule.db_instance_cloudwatch_logs|
|message|data.rule.db_instance_cloudwatch_logs_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html#cfn-rds-dbinstance-enablecloudwatchlogsexports' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_RDS_018.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Use CloudWatch logging types for Amazon Relational Database Service (Amazon RDS) instances  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::rds::dbinstance']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego
