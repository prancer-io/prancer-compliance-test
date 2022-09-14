



# Master Test ID: PR-AWS-CLD-S3-024


Master Snapshot Id: ['TEST_S3']

type: rego

rule: [file(storage.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-S3-024|
|eval: |data.rule.s3_has_a_policy_attached|
|message: |data.rule.s3_has_a_policy_attached_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.get_bucket_policy' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_S3_024.py|


severity: Low

title: Ensure AWS S3 bucket has a policy attached.

description: S3 access can be defined at IAM and Bucket policy levels. It is recommended to leverage bucket policies as it provide much more granularity. This controls check if a bucket has a custom policy attached to it.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['Best Practice']|
|service: |['cloud']|



[file(storage.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
