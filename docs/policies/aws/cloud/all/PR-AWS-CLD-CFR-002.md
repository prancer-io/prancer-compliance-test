



# Master Test ID: PR-AWS-CLD-CFR-002


Master Snapshot Id: ['TEST_ALL_16']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-CFR-002|
|eval: |data.rule.cloudFormation_template_configured_with_stack_policy|
|message: |data.rule.cloudFormation_template_configured_with_stack_policy_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudformation.html#CloudFormation.Client.get_stack_policy' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_CFR_002.py|


severity: Low

title: Ensure CloudFormation template is configured with stack policy.

description: In AWS IAM policy governs how much access/permission the stack has and if no policy is provided it assumes the permissions of the user running it.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['NIST 800']|
|service: |['cloudformation']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
