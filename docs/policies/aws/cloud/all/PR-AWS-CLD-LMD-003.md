



# Master Test ID: PR-AWS-CLD-LMD-003


***<font color="white">Master Snapshot Id:</font>*** ['TEST_LAMBDA']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([lambda.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-LMD-003|
|eval|data.rule.lambda_tracing|
|message|data.rule.lambda_tracing_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_LMD_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** AWS Lambda functions with tracing not enabled

***<font color="white">Description:</font>*** TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors._x005F_x000D_ _x005F_x000D_ The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['HITRUST', 'NIST 800']|
|service|['lambda']|



[lambda.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/lambda.rego
