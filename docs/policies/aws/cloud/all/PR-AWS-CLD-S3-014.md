



# Master Test ID: PR-AWS-CLD-S3-014


Master Snapshot Id: ['TEST_S3']

type: rego

rule: [file(storage.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-S3-014|
|eval: |data.rule.s3_cors|
|message: |data.rule.s3_cors_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#aws-properties-s3-bucket--seealso' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_S3_014.py|


severity: Medium

title: Ensure S3 hosted sites supported hardened CORS

description: Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['Best Practice']|
|service: |['cloud']|



[file(storage.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
