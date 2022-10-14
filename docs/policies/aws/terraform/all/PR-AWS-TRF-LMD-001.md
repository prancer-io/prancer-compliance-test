



# Title: AWS Lambda Environment Variables not encrypted at-rest using CMK


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-LMD-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([lambda.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-LMD-001|
|eval|data.rule.lambda_env|
|message|data.rule.lambda_env_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_LMD_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code.<br><br>This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_lambda_function']


[lambda.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego
