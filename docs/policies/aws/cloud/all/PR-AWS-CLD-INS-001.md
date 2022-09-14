



# Master Test ID: PR-AWS-CLD-INS-001


Master Snapshot Id: ['TEST_ALL_15']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-INS-001|
|eval: |data.rule.ins_package|
|message: |data.rule.ins_package_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_INS_001.py|


severity: High

title: Enable AWS Inspector to detect Vulnerability

description: Enable AWS Inspector to detect Vulnerability  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['inspector']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
