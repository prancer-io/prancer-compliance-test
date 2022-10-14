



# Title: Ensure AWS RDS DB authentication is only enabled via IAM


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-RDS-027

***<font color="white">Master Snapshot Id:</font>*** ['TEST_RDS_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-RDS-027|
|eval|data.rule.rds_iam_database_auth|
|message|data.rule.rds_iam_database_auth_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_RDS_027.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy checks RDS DB instances which are not configured with IAM based authentication and using any hardcoded credentials.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Secure access management', 'NZISM', 'New Zealand Information Security Manual (NZISM v3.4)-16.1']|
|service|['rds']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
