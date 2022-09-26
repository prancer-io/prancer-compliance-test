



# Title: Ensure unsupported properties on Lambda EventSourceMapping are not set.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-LMD-006

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([lambda.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-LMD-006|
|eval|data.rule.lambda_eventsourcemapping_unsupported_properties|
|message|data.rule.lambda_eventsourcemapping_unsupported_properties_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html#cfn-lambda-function-deadletterconfig' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_LMD_006.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Ensure that unsupported properties on AWS::Lambda::EventSourceMapping are not set  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::lambda::eventsourcemapping']


[lambda.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego
