



# Title: Ensure S3 bucket RestrictPublicBucket is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-S3-019

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-S3-019|
|eval|data.rule.s3_restrict_public_bucket|
|message|data.rule.s3_restrict_public_bucket_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_S3_019.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_s3_bucket_public_access_block']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego
