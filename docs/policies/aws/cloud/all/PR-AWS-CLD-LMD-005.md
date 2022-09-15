



# Master Test ID: PR-AWS-CLD-LMD-005


***<font color="white">Master Snapshot Id:</font>*** ['TEST_LAMBDA']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([lambda.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-LMD-005|
|eval|data.rule.lambda_dlq|
|message|data.rule.lambda_dlq_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html#cfn-lambda-function-deadletterconfig' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_LMD_005.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** Ensure AWS Lambda function is configured for a DLQ

***<font color="white">Description:</font>*** A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['lambda']|



[lambda.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/lambda.rego
