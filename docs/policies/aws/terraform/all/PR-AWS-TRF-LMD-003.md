



# Title: AWS Lambda functions with tracing not enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-LMD-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([lambda.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-LMD-003|
|eval|data.rule.lambda_tracing|
|message|data.rule.lambda_tracing_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_LMD_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors.<br><br>The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HITRUST', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_lambda_function']


[lambda.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego
