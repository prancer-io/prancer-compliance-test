



# Title: AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-S3-002

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-S3-002|
|eval|data.rule.s3_acl_delete|
|message|data.rule.s3_acl_delete_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_S3_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to DELETE objects from a bucket. These permissions permit anyone, malicious or not, to DELETE objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::s3::bucketpolicy']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego
