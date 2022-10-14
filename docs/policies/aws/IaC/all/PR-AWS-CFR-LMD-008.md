



# Title: Limit lambda runtimes to allowed list


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-LMD-008

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([lambda.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-LMD-008|
|eval|data.rule.lambda_runtime|
|message|data.rule.lambda_runtime_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html#cfn-lambda-function-deadletterconfig' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_LMD_008.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Ensure that AWS::Lambda::Function Runtime values are limited to a vetted list of allowed runtimes  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::lambda::function']


[lambda.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego
