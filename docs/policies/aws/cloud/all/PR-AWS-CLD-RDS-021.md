



# Master Test ID: PR-AWS-CLD-RDS-021


***<font color="white">Master Snapshot Id:</font>*** ['TEST_RDS_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-RDS-021|
|eval|data.rule.db_instance_engine_version|
|message|data.rule.db_instance_engine_version_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html#aws-properties-rds-database-instance--examples' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_RDS_021.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure RDS instances do not use a deprecated version of Aurora-PostgreSQL.

***<font color="white">Description:</font>*** AWS Aurora PostgreSQL which is exposed to local file read vulnerability. It is highly recommended to upgrade AWS Aurora PostgreSQL to the latest version.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'GDPR', 'CIS', 'HITRUST', 'NIST 800', 'HIPAA', 'ISO 27001', 'SOC 2']|
|service|['rds']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
