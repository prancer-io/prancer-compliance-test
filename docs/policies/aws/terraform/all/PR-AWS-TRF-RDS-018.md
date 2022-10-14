



# Title: Ensure respective logs of Amazon RDS instance are enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-RDS-018

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-RDS-018|
|eval|data.rule.db_instance_cloudwatch_logs|
|message|data.rule.db_instance_cloudwatch_logs_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_RDS_018.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Use CloudWatch logging types for Amazon Relational Database Service (Amazon RDS) instances  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_db_instance']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
