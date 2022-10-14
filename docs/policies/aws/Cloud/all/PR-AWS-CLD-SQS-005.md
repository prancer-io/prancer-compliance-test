



# Title: Ensure SQS policy documents do not allow all actions


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-SQS-005

***<font color="white">Master Snapshot Id:</font>*** ['TEST_SQS']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sqs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-SQS-005|
|eval|data.rule.sqs_policy_action|
|message|data.rule.sqs_policy_action_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queuepolicy.html#cfn-sqs-queuepolicy-policydocument' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_SQS_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This level of access could potentially grant unwanted and unregulated access to anyone given this policy document setting. We recommend you to write a refined policy describing the specific action allowed or required by the specific policy holder  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['sqs']|



[sqs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/sqs.rego
