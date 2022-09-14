



# Master Test ID: PR-AWS-CLD-CFR-004


Master Snapshot Id: ['TEST_ALL_14']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-CFR-004|
|eval: |data.rule.role_arn_exist|
|message: |data.rule.role_arn_exist_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudformation.html#CloudFormation.Client.describe_stacks' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_CFR_004.py|


severity: Low

title: Ensure an IAM policy is defined with the stack.

description: Stack policy protects resources from accidental updates, the policy included resources which shouldn't be updated during the template provisioning process.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['NIST 800']|
|service: |['cloudformation']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
