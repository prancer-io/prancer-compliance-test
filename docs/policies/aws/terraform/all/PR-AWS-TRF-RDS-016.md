



# Title: Ensure RDS cluster has IAM authentication enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-RDS-016

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-RDS-016|
|eval|data.rule.cluster_iam_authenticate|
|message|data.rule.cluster_iam_authenticate_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_RDS_016.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure IAM Database Authentication feature is enabled in order to use AWS Identity and Access Management (IAM) service to manage database access to your Amazon RDS MySQL and PostgreSQL instances. With this feature enabled, you don't have to use a password when you connect to your MySQL/PostgreSQL database instances, instead you use an authentication token  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_rds_cluster']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
