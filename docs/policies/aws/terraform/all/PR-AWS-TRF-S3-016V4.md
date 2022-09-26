



# Title: Ensure S3 bucket has enabled lock configuration


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-S3-016V4

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-S3-016V4|
|eval|data.rule.s3_object_lock_enable_v4|
|message|data.rule.s3_object_lock_enable_v4_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_S3_016v4.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Indicates whether this bucket has an Object Lock configuration enabled. Enable object_lock_enabled when you apply ObjectLockConfiguration to a bucket.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_s3_bucket_object_lock_configuration']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego
