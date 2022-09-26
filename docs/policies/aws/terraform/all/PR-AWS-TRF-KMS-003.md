



# Title: Ensure no KMS key policy contain wildcard (*) principal


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-KMS-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([kms.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-KMS-003|
|eval|data.rule.kms_key_allow_all_principal|
|message|data.rule.kms_key_allow_all_principal_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_KMS_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy revents all user access to specific resource/s and actions  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_kms_key']


[kms.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/kms.rego
