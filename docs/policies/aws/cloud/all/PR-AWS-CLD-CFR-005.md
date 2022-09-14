



# Master Test ID: PR-AWS-CLD-CFR-005


Master Snapshot Id: ['TEST_ALL_14']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-CFR-005|
|eval: |data.rule.stack_with_not_all_capabilities|
|message: |data.rule.stack_with_not_all_capabilities_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudformation.html#CloudFormation.Client.describe_stacks' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_CFR_005.py|


severity: Medium

title: Ensure capabilities in stacks do not have * in it.

description: A CloudFormation stack needs certain capability, It is recommended to configure the stack with capabilities not all capabilities (*) should be configured. This will give the stack unlimited access.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['NIST 800']|
|service: |['cloudformation']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
