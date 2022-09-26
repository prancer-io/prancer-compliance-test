



# Title: Ensure PGAudit is enabled on RDS Postgres instances


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-RDS-014

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-RDS-014|
|eval|data.rule.rds_pgaudit_enable|
|message|data.rule.rds_pgaudit_enable_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_parameter_group' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_RDS_014.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Postgres database instances can be enabled for auditing with PGAudit, the PostgresSQL Audit Extension. With PGAudit enabled you will be able to audit any database, its roles, relations, or columns.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_db_parameter_group']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
