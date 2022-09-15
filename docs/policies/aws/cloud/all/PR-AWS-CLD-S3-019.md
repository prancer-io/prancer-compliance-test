



# Master Test ID: PR-AWS-CLD-S3-019


***<font color="white">Master Snapshot Id:</font>*** ['TEST_S3']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-S3-019|
|eval|data.rule.s3_restrict_public_bucket|
|message|data.rule.s3_restrict_public_bucket_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html#cfn-s3-bucket-publicaccessblockconfiguration-restrictpublicbuckets' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_S3_019.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure S3 bucket RestrictPublicBucket is enabled

***<font color="white">Description:</font>*** Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['Best Practice']|
|service|['cloud']|



[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
