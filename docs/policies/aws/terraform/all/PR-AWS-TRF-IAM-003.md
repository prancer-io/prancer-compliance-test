



# Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-IAM-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-IAM-003|
|eval|data.rule.iam_wildcard_principal|
|message|data.rule.iam_wildcard_principal_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_IAM_003.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_iam_role']


[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego
