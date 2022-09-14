



# Master Test ID: PR-AWS-CLD-MSK-001


Master Snapshot Id: ['TEST_MSK']

type: rego

rule: [file(msk.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-MSK-001|
|eval: |data.rule.msk_encryption_at_rest_cmk|
|message: |data.rule.msk_encryption_at_rest_cmk_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_MSK_001.py|


severity: Medium

title: Use KMS Customer Master Keys for AWS MSK Clusters

description: Ensure that Amazon Managed Streaming for Kafka (MSK) clusters are using AWS KMS Customer Master Keys (CMKs) instead of AWS managed-keys (i.e. default keys) for data encryption, in order to have a fine-grained control over data-at-rest encryption/decryption process and meet compliance requirements. MSK is a fully managed AWS service that enables you to migrate, build and run real-time streaming applications on Apache Kafka.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['Best Practice']|
|service: |['msk']|



[file(msk.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/msk.rego
