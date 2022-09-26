



# Title: Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*'


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-IAM-004

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-IAM-004|
|eval|data.rule.iam_resource_format|
|message|data.rule.iam_resource_format_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_user_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_IAM_004.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*' AWS only allows fully qualified ARNs or '*'. The above mentioned ARN is not supported in an identity-based policy  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_iam_user_policy', 'aws_iam_role', 'aws_iam_group_policy']


[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego
