



# Master Test ID: PR-AWS-CLD-RDS-024


Master Snapshot Id: ['TEST_RDS_02']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-RDS-024|
|eval: |data.rule.db_cluster_approved_postgres_version|
|message: |data.rule.db_cluster_approved_postgres_version_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html#aws-resource-rds-dbcluster--examples' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_RDS_024.py|


severity: Medium

title: Ensure RDS dbcluster do not use a deprecated version of PostgreSQL.

description: AWS RDS PostgreSQL which is exposed to local file read vulnerability. It is highly recommended to upgrade AWS RDS PostgreSQL to the latest version.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['PCI DSS', 'GDPR', 'CIS', 'HITRUST', 'NIST 800', 'HIPAA', 'ISO 27001', 'SOC 2']|
|service: |['rds']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
