



# Master Test ID: PR-AWS-CLD-KMS-004


Master Snapshot Id: ['TEST_KMS']

type: rego

rule: [file(kms.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-KMS-004|
|eval: |data.rule.kms_key_not_schedule_deletion|
|message: |data.rule.kms_key_not_schedule_deletion_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kms.html#KMS.Client.describe_key' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_KMS_004.py|


severity: Medium

title: Ensure AWS KMS Key is not scheduled for deletion.

description: It identifies KMS Keys which are scheduled for deletion. Deleting keys in AWS KMS is destructive and potentially dangerous. It deletes the key material and all metadata associated with it and is irreversible. After a key is deleted, you can no longer decrypt the data that was encrypted under that key, which means that data becomes unrecoverable. You should delete a key only when you are sure that you don't need to use it anymore. If you are not sure, It is recommended that to disable the key instead of deleting it.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['kms']|



[file(kms.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/kms.rego
