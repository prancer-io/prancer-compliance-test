



# Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-LMD-004

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([lambda.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-LMD-004|
|eval|data.rule.lambda_concurrent_execution|
|message|data.rule.lambda_concurrent_execution_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_LMD_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_lambda_function']


[lambda.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego
