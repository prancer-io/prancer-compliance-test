



# Master Test ID: PR-AWS-CLD-S3-013


Master Snapshot Id: ['TEST_S3']

type: rego

rule: [file(storage.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-S3-013|
|eval: |data.rule.s3_website|
|message: |data.rule.s3_website_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_S3_013.py|


severity: Medium

title: S3 buckets with configurations set to host websites

description: To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['ISO 27001', 'NIST 800']|
|service: |['cloud']|



[file(storage.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
