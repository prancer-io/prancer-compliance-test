



# Master Test ID: PR-AWS-CLD-S3-026


***<font color="white">Master Snapshot Id:</font>*** ['TEST_S3']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-S3-026|
|eval|data.rule.s3_only_owner_access|
|message|data.rule.s3_only_owner_access_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.get_bucket_acl' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_S3_026.py|


***<font color="white">Severity:</font>*** low

***<font color="white">Title:</font>*** Ensure S3 bucket ACL is in use and any user other than the owner does not have any access on it.

***<font color="white">Description:</font>*** It ensure the S3 access control list only allowed owner permissions. It checks if other AWs accounts are granted Read/Write access to the S3 bucket.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['cloud']|



[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
