



# Master Test ID: PR-AWS-CLD-LMD-001


***<font color="white">Master Snapshot Id:</font>*** ['TEST_LAMBDA']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([lambda.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-LMD-001|
|eval|data.rule.lambda_env|
|message|data.rule.lambda_env_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_LMD_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** AWS Lambda Environment Variables not encrypted at-rest using CMK

***<font color="white">Description:</font>*** When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['GDPR', 'CSA CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF']|
|service|['lambda']|



[lambda.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/lambda.rego
