



# Master Test ID: PR-AWS-CLD-RDS-014


Master Snapshot Id: ['TEST_RDS_03']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-RDS-014|
|eval: |data.rule.rds_pgaudit_enable|
|message: |data.rule.rds_pgaudit_enable_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-dbparametergroup.html#cfn-rds-dbparametergroup-parameters' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_RDS_014.py|


severity: Medium

title: Ensure PGAudit is enabled on RDS Postgres instances

description: Postgres database instances can be enabled for auditing with PGAudit, the PostgresSQL Audit Extension. With PGAudit enabled you will be able to audit any database, its roles, relations, or columns.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['rds']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
