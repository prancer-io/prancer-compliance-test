



# Master Test ID: PR-AWS-CLD-RDS-029


***<font color="white">Master Snapshot Id:</font>*** ['TEST_RDS_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-RDS-029|
|eval|data.rule.db_instance_deletion_protection|
|message|data.rule.db_instance_deletion_protection_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html#RDS.Client.describe_db_instances' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_RDS_029.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** Ensure AWS RDS DB instance has deletion protection enabled.

***<font color="white">Description:</font>*** It is to check that deletion protection in enabled at RDS DB level in order to protect the DB instance from accidental deletion.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Data protection', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1485 - Data Destruction', 'NZISM', 'New Zealand Information Security Manual (NZISM v3.4)-22.1']|
|service|['rds']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
