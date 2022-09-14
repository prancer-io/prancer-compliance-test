



# Master Test ID: PR-AWS-CLD-SQS-005


Master Snapshot Id: ['TEST_SQS']

type: rego

rule: [file(sqs.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-SQS-005|
|eval: |data.rule.sqs_policy_action|
|message: |data.rule.sqs_policy_action_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queuepolicy.html#cfn-sqs-queuepolicy-policydocument' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_SQS_005.py|


severity: Medium

title: Ensure SQS policy documents do not allow all actions

description: This level of access could potentially grant unwanted and unregulated access to anyone given this policy document setting. We recommend you to write a refined policy describing the specific action allowed or required by the specific policy holder  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['sqs']|



[file(sqs.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/sqs.rego
