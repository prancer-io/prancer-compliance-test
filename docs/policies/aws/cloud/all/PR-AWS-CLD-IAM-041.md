



# Master Test ID: PR-AWS-CLD-IAM-041


Master Snapshot Id: ['TEST_IAM_01']

type: rego

rule: [file(iam.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-IAM-041|
|eval: |data.rule.not_allow_decryption_actions_on_all_kms_keys|
|message: |data.rule.not_allow_decryption_actions_on_all_kms_keys_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_policy_versions' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_IAM_041.py|


severity: Medium

title: Ensure AWS IAM policy does not allows decryption actions on all KMS keys.

description: It identifies IAM policies that allow decryption actions on all KMS keys. Instead of granting permissions for all keys, determine the minimum set of keys that users need to access encrypted data. You should grant to identities only the kms:Decrypt or kms:ReEncryptFrom permissions and only for the keys that are required to perform a task. By adopting the principle of least privilege, you can reduce the risk of unintended disclosure of your data.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['AWS Well-Architected Framework', 'AWS Well-Architected Framework-Identity and Access Management']|
|service: |['iam']|



[file(iam.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/iam.rego
