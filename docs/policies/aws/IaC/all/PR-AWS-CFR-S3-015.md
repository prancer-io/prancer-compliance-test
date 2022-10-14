



# Title: Ensure S3 bucket is encrypted using KMS


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-S3-015

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-S3-015|
|eval|data.rule.bucket_kms_encryption|
|message|data.rule.bucket_kms_encryption_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-serversideencryptionbydefault.html#cfn-s3-bucket-serversideencryptionbydefault-ssealgorithm' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_S3_015.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800', 'GDPR']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::s3::bucket']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego
