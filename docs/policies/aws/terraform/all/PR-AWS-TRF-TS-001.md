



# Title: Ensure Timestream database is encrypted using KMS


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-TS-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-TS-001|
|eval|data.rule.timestream_database_encryption|
|message|data.rule.timestream_database_encryption_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/timestreamwrite_database' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_TS_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The timestream databases must be secured with KMS instead of default kms.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_timestreamwrite_database']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
