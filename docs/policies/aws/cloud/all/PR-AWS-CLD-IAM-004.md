



# Master Test ID: PR-AWS-CLD-IAM-004


Master Snapshot Id: ['TEST_IAM_01']

type: rego

rule: [file(iam.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-IAM-004|
|eval: |data.rule.iam_resource_format|
|message: |data.rule.iam_resource_format_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_IAM_004.py|


severity: High

title: Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*'

description: Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*' AWS only allows fully qualified ARNs or '*'. The above mentioned ARN is not supported in an identity-based policy  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['CIS', 'NIST 800']|
|service: |['iam']|



[file(iam.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/iam.rego
