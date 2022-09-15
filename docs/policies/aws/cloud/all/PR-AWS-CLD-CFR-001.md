



# Master Test ID: PR-AWS-CLD-CFR-001


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_14']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-CFR-001|
|eval|data.rule.cf_sns|
|message|data.rule.cf_sns_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-stack.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_CFR_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** AWS CloudFormation stack configured without SNS topic

***<font color="white">Description:</font>*** This policy identifies CloudFormation stacks which are configured without SNS topic. It is recommended to configure Simple Notification Service (SNS) topic to be notified of CloudFormation stack status and changes.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['NIST 800']|
|service|['cloudformation']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
