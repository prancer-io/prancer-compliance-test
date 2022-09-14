



# Master Test ID: PR-AWS-CLD-SM-001


Master Snapshot Id: ['TEST_ALL_02']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-SM-001|
|eval: |data.rule.secret_manager_kms|
|message: |data.rule.secret_manager_kms_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_SM_001.py|


severity: High

title: Ensure that Secrets Manager secret is encrypted using KMS

description: Ensure that your Amazon Secrets Manager secrets (i.e. database credentials, API keys, OAuth tokens, etc) are encrypted with Amazon KMS Customer Master Keys instead of default encryption keys that Secrets Manager service creates for you, in order to have a more control over secret data encryption and decryption process  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['GDPR', 'NIST 800']|
|service: |['secret manager']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
