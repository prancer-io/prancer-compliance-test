



# Title: Ensure S3 bucket has enabled lock configuration


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-S3-016

***<font color="white">Master Snapshot Id:</font>*** ['TEST_S3']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-S3-016|
|eval|data.rule.s3_object_lock_enable|
|message|data.rule.s3_object_lock_enable_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-objectlockenabled' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_S3_016.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['NIST 800']|
|service|['cloud']|



[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
