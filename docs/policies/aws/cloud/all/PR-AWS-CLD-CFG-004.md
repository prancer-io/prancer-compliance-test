



# Master Test ID: PR-AWS-CLD-CFG-004


Master Snapshot Id: ['TEST_ALL_09']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-CFG-004|
|eval: |data.rule.config_includes_global_resources|
|message: |data.rule.config_includes_global_resources_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-config-configurationrecorder.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_CFG_004.py|


severity: Low

title: Ensure AWS Config includes global resources types (IAM).

description: It checks that global resource types are included in AWS Config.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['config']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
