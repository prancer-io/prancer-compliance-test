



# Master Test ID: PR-AWS-CLD-CFR-006


Master Snapshot Id: ['TEST_ALL_14']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-CFR-006|
|eval: |data.rule.termination_protection_in_stacks_is_enabled|
|message: |data.rule.termination_protection_in_stacks_is_enabled_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudformation.html#CloudFormation.Client.describe_stacks' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_CFR_006.py|


severity: Low

title: Ensure termination protection in stacks is enabled.

description: It checks if the stack is protected against accidental termination which may lead to deletion of critical resources.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['NIST 800']|
|service: |['cloudformation']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
