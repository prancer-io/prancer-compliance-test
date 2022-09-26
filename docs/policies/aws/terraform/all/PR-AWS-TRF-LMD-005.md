



# Title: Ensure AWS Lambda function is configured for a DLQ


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-LMD-005

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([lambda.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-LMD-005|
|eval|data.rule.lambda_dlq|
|message|data.rule.lambda_dlq_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_LMD_005.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_lambda_function']


[lambda.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego
