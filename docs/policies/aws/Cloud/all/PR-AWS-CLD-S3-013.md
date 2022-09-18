



# Title: S3 buckets with configurations set to host websites


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-S3-013

***<font color="white">Master Snapshot Id:</font>*** ['TEST_S3']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-S3-013|
|eval|data.rule.s3_website|
|message|data.rule.s3_website_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_S3_013.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['ISO 27001', 'NIST 800']|
|service|['cloud']|



[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
