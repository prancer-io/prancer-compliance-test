



# Title: Ensure RDS DB instance has setup backup retention period of at least 30 days.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-RDS-030

***<font color="white">Master Snapshot Id:</font>*** ['TEST_RDS_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-RDS-030|
|eval|data.rule.db_instance_backup_retention_period|
|message|data.rule.db_instance_backup_retention_period_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html#RDS.Client.describe_db_instances' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_RDS_030.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This is to check that backup retention period for RDS DB is firm approved.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'GDPR', 'CIS', 'HITRUST', 'NIST 800', 'HIPAA', 'ISO 27001', 'SOC 2']|
|service|['rds']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
