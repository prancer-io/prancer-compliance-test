



# Title: AWS S3 Bucket has Global LIST Permissions enabled via bucket policy


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-S3-004

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-S3-004|
|eval|data.rule.s3_acl_list|
|message|data.rule.s3_acl_list_err|
|remediationDescription|Make sure you are following the Terraform template format presented https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy|
|remediationFunction|PR_AWS_TRF_S3_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to LIST objects from a bucket. These permissions permit anyone, malicious or not, to LIST objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_s3_bucket_policy']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego
