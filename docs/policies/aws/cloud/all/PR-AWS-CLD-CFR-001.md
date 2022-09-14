



# Master Test ID: PR-AWS-CLD-CFR-001


Master Snapshot Id: ['TEST_ALL_14']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-CFR-001|
|eval: |data.rule.cf_sns|
|message: |data.rule.cf_sns_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-stack.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_CFR_001.py|


severity: Medium

title: AWS CloudFormation stack configured without SNS topic

description: This policy identifies CloudFormation stacks which are configured without SNS topic. It is recommended to configure Simple Notification Service (SNS) topic to be notified of CloudFormation stack status and changes.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['NIST 800']|
|service: |['cloudformation']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
