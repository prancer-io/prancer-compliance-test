



# Title: Lambda Function PackageType value is limited to Zip


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-LMD-007

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([lambda.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-LMD-007|
|eval|data.rule.lambda_require_zip_package|
|message|data.rule.lambda_require_zip_package_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html#cfn-lambda-function-deadletterconfig' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_LMD_007.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Ensure that the AWS::Lambda::Function PackageType value is limited to Zip.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::lambda::function']


[lambda.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego
