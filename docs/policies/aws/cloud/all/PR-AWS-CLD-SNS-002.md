



# Master Test ID: PR-AWS-CLD-SNS-002


Master Snapshot Id: ['TEST_SNS_02']

type: rego

rule: [file(sns.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-SNS-002|
|eval: |data.rule.sns_encrypt_key|
|message: |data.rule.sns_encrypt_key_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_SNS_002.py|


severity: High

title: AWS SNS topic encrypted using default KMS key instead of CMK

description: This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['GDPR', 'NIST 800']|
|service: |['sns']|



[file(sns.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/sns.rego
