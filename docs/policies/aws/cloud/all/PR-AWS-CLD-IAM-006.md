



# Master Test ID: PR-AWS-CLD-IAM-006


Master Snapshot Id: ['TEST_IAM_01']

type: rego

rule: [file(iam.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-IAM-006|
|eval: |data.rule.iam_all_traffic|
|message: |data.rule.iam_all_traffic_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_IAM_006.py|


severity: Medium

title: AWS IAM policy is overly permissive to all traffic via condition clause

description: This policy identifies IAM policies that have a policy that is overly permissive to all traffic via condition clause. If any IAM policy statement with a condition containing 0.0.0.0/0 or ::/0, it allows all traffic to resources attached to that IAM policy. It is highly recommended to have the least privileged IAM policy to protect the data leakage and unauthorized access.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['CIS']|
|service: |['iam']|



[file(iam.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/iam.rego
