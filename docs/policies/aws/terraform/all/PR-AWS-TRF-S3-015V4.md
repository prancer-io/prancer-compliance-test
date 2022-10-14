



# Title: Ensure S3 bucket is encrypted using KMS


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-S3-015V4

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-S3-015V4|
|eval|data.rule.bucket_kms_encryption_v4|
|message|data.rule.bucket_kms_encryption_v4_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_S3_015V4.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800', 'GDPR']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_s3_bucket_server_side_encryption_configuration']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego
