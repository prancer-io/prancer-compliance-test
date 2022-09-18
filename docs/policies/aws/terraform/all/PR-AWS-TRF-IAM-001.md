



# Title: Ensure no wildcards are specified in IAM policy with 'Resource' section


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-IAM-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-IAM-001|
|eval|data.rule.iam_wildcard_resource|
|message|data.rule.iam_wildcard_resource_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_IAM_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Using a wildcard in the Resource element in a role's trust policy would allow any IAM user in an account to access all resources. This is a significant security gap and can be used to gain access to sensitive data.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_iam_policy']


[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego
