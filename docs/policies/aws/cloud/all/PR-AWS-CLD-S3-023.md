



# Master Test ID: PR-AWS-CLD-S3-023


Master Snapshot Id: ['TEST_S3']

type: rego

rule: [file(storage.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-S3-023|
|eval: |data.rule.s3_overly_permissive_to_any_principal|
|message: |data.rule.s3_overly_permissive_to_any_principal_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.get_bucket_policy' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_S3_023.py|


severity: Medium

title: Ensure AWS S3 bucket policy is not overly permissive to any principal.

description: It identifies the S3 buckets that have a bucket policy overly permissive to any principal. It is recommended to follow the principle of least privileges ensuring that the only restricted entities have permission on S3 operations instead of any anonymous. For more details: https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-bucket-user-policy-specifying-principal-intro.html  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['AWS Well-Architected Framework', 'AWS Well-Architected Framework-Data Protection']|
|service: |['cloud']|



[file(storage.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
