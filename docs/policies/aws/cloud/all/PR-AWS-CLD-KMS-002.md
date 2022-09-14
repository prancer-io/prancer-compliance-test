



# Master Test ID: PR-AWS-CLD-KMS-002


Master Snapshot Id: ['TEST_KMS']

type: rego

rule: [file(kms.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-KMS-002|
|eval: |data.rule.kms_key_state|
|message: |data.rule.kms_key_state_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html#cfn-kms-key-enablekeyrotation' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_KMS_002.py|


severity: Medium

title: AWS KMS Customer Managed Key not in use

description: This policy identifies KMS Customer Managed Keys(CMKs) which are not usable. When you create a CMK, it is enabled by default. If you disable a CMK or schedule it for deletion makes it unusable, it cannot be used to encrypt or decrypt data and AWS KMS does not rotate the backing keys until you re-enable it.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['Best Practice']|
|service: |['kms']|



[file(kms.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/kms.rego
