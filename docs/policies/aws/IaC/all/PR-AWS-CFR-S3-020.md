



# Title: Ensure S3 bucket IgnorePublicAcls is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-S3-020

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-S3-020|
|eval|data.rule.s3_ignore_public_acl|
|message|data.rule.s3_ignore_public_acl_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html#cfn-s3-bucket-publicaccessblockconfiguration-ignorepublicacls' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_S3_020.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::s3::bucket']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego
