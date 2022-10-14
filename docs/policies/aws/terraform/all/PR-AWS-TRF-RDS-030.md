



# Title: Ensure RDS DB instance has setup backup retention period of at least 30 days.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-RDS-030

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-RDS-030|
|eval|data.rule.db_instance_backup_retention_period|
|message|data.rule.db_instance_backup_retention_period_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_RDS_030.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This is to check that backup retention period for RDS DB is firm approved.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI DSS', 'GDPR', 'CIS', 'HITRUST', 'NIST 800', 'HIPAA', 'ISO 27001', 'SOC 2']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_db_instance']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
