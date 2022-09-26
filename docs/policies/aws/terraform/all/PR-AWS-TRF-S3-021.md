



# Title: Ensure S3 Bucket block_public_policy is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-S3-021

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-S3-021|
|eval|data.rule.s3_block_public_policy|
|message|data.rule.s3_block_public_policy_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_S3_021.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_s3_bucket_public_access_block']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego
