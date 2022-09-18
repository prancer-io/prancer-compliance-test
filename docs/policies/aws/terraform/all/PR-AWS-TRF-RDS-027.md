



# Title: Ensure AWS RDS DB authentication is only enabled via IAM.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-RDS-027

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-RDS-027|
|eval|data.rule.rds_iam_database_auth|
|message|data.rule.rds_iam_database_auth_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_RDS_027.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy checks RDS DB instances which are not configured with IAM based authentication and using any hardcoded credentials.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Secure access management', 'NZISM', 'New Zealand Information Security Manual (NZISM v3.4)-16.1']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_db_instance']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
