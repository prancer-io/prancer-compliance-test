



# Title: Dynamo DB kinesis specification property should not be null


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-DD-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-DD-003|
|eval|data.rule.dynamodb_kinesis_stream|
|message|data.rule.dynamodb_kinesis_stream_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table#stream_arn' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_DD_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Dynamo DB kinesis specification property should not be null  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_dynamodb_table']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
