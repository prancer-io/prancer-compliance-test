



# Title: Ensure CloudFormation template is configured with stack policy.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-CFR-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-CFR-002|
|eval|data.rule.cloudFormation_template_configured_with_stack_policy|
|message|data.rule.cloudFormation_template_configured_with_stack_policy_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudformation_stack' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_CFR_002.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** In AWS IAM policy governs how much access/permission the stack has and if no policy is provided it assumes the permissions of the user running it.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_cloudformation_stack']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
