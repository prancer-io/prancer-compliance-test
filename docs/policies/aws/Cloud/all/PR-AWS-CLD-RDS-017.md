



# Title: Ensure RDS instace has IAM authentication enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-RDS-017

***<font color="white">Master Snapshot Id:</font>*** ['TEST_RDS_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-RDS-017|
|eval|data.rule.db_instance_iam_authenticate|
|message|data.rule.db_instance_iam_authenticate_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html#cfn-rds-dbinstance-enableiamdatabaseauthentication' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_RDS_017.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure IAM Database Authentication feature is enabled in order to use AWS Identity and Access Management (IAM) service to manage database access to your Amazon RDS MySQL and PostgreSQL instances. With this feature enabled, you don't have to use a password when you connect to your MySQL/PostgreSQL database instances, instead you use an authentication token  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['NIST 800']|
|service|['rds']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
