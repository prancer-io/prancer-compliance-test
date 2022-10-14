



# Title: Ensure no KMS key policy contain wildcard (*) principal


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-KMS-003

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([kms.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-KMS-003|
|eval|data.rule.kms_key_allow_all_principal|
|message|data.rule.kms_key_allow_all_principal_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_KMS_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy revents all user access to specific resource/s and actions  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::kms::key']


[kms.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/kms.rego
