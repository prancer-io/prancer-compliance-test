



# Title: Ensure CloudWatch log groups are encrypted with KMS CMKs


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-LG-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-LG-001|
|eval|data.rule.log_group_encryption|
|message|data.rule.log_group_encryption_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_LG_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** CloudWatch log groups are encrypted by default. However, utilizing KMS CMKs gives you more control over key rotation and provides auditing visibility into key usage.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_cloudwatch_log_group']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
