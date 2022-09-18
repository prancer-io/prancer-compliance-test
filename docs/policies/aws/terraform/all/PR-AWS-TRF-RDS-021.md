



# Title: Ensure RDS instances do not use a deprecated version of Aurora-PostgreSQL.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-RDS-021

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-RDS-021|
|eval|data.rule.db_instance_engine_version|
|message|data.rule.db_instance_engine_version_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_RDS_021.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** AWS Aurora PostgreSQL which is exposed to local file read vulnerability. It is highly recommended to upgrade AWS Aurora PostgreSQL to the latest version.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'GDPR', 'CIS', 'HITRUST', 'NIST 800', 'HIPAA', 'ISO 27001', 'SOC 2']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_db_instance']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
