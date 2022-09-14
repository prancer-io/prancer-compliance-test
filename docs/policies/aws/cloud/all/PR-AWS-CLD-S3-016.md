



# Master Test ID: PR-AWS-CLD-S3-016


Master Snapshot Id: ['TEST_S3']

type: rego

rule: [file(storage.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-S3-016|
|eval: |data.rule.s3_object_lock_enable|
|message: |data.rule.s3_object_lock_enable_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-objectlockenabled' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_S3_016.py|


severity: Low

title: Ensure S3 bucket has enabled lock configuration

description: Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['NIST 800']|
|service: |['cloud']|



[file(storage.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
