



# Title: Ensure AWS RDS DB instance has deletion protection enabled.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-RDS-029

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-RDS-029|
|eval|data.rule.db_instance_deletion_protection|
|message|data.rule.db_instance_deletion_protection_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_RDS_029.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It is to check that deletion protection in enabled at RDS DB level in order to protect the DB instance from accidental deletion.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Data protection', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1485 - Data Destruction', 'NZISM', 'New Zealand Information Security Manual (NZISM v3.4)-22.1']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_db_instance']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
