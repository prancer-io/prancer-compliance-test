



# Master Test ID: PR-AWS-CLD-S3-015


Master Snapshot Id: ['TEST_S3']

type: rego

rule: [file(storage.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-S3-015|
|eval: |data.rule.bucket_kms_encryption|
|message: |data.rule.bucket_kms_encryption_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-serversideencryptionbydefault.html#cfn-s3-bucket-serversideencryptionbydefault-ssealgorithm' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_S3_015.py|


severity: Medium

title: Ensure S3 bucket is encrypted using KMS

description: Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['NIST 800', 'GDPR']|
|service: |['cloud']|



[file(storage.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
