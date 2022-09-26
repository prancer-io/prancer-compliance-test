



# Title: Ensure AWS S3 bucket policy is not overly permissive to any principal.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-S3-023

***<font color="white">Master Snapshot Id:</font>*** ['TEST_S3']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-S3-023|
|eval|data.rule.s3_overly_permissive_to_any_principal|
|message|data.rule.s3_overly_permissive_to_any_principal_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.get_bucket_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_S3_023.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It identifies the S3 buckets that have a bucket policy overly permissive to any principal. It is recommended to follow the principle of least privileges ensuring that the only restricted entities have permission on S3 operations instead of any anonymous. For more details: https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-bucket-user-policy-specifying-principal-intro.html  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['AWS Well-Architected Framework', 'AWS Well-Architected Framework-Data Protection']|
|service|['cloud']|



[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
