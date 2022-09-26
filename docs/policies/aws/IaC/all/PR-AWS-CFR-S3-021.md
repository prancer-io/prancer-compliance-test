



# Title: Ensure S3 Bucket BlockPublicPolicy is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-S3-021

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-S3-021|
|eval|data.rule.s3_block_public_policy|
|message|data.rule.s3_block_public_policy_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html#cfn-s3-bucket-publicaccessblockconfiguration-blockpublicpolicy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_S3_021.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::s3::bucket']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego
