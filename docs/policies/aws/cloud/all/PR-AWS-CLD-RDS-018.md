



# Master Test ID: PR-AWS-CLD-RDS-018


Master Snapshot Id: ['TEST_RDS_01']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-RDS-018|
|eval: |data.rule.db_instance_cloudwatch_logs|
|message: |data.rule.db_instance_cloudwatch_logs_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html#cfn-rds-dbinstance-enablecloudwatchlogsexports' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_RDS_018.py|


severity: Low

title: Ensure respective logs of Amazon RDS instance are enabled

description: Use CloudWatch logging types for Amazon Relational Database Service (Amazon RDS) instances  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['rds']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
