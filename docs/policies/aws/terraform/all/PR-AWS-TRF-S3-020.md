



# Title: Ensure S3 bucket ignore_public_acls is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-S3-020

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-S3-020|
|eval|data.rule.s3_ignore_public_acl|
|message|data.rule.s3_ignore_public_acl_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_S3_020.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_s3_bucket_public_access_block']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego
