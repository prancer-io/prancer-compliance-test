



# Master Test ID: PR-AWS-CLD-IAM-001


Master Snapshot Id: ['TEST_IAM_01']

type: rego

rule: [file(iam.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-IAM-001|
|eval: |data.rule.iam_wildcard_resource|
|message: |data.rule.iam_wildcard_resource_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_IAM_001.py|


severity: High

title: Ensure no wildcards are specified in IAM policy with 'Resource' section

description: Using a wildcard in the Resource element in a role's trust policy would allow any IAM user in an account to access all Resources. This is a significant security gap and can be used to gain access to sensitive data.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['CIS', 'NIST 800']|
|service: |['iam']|



[file(iam.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/iam.rego
