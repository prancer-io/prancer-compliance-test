



# Title: Ensure capabilities in stacks do not have * in it.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-CFR-005

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-CFR-005|
|eval|data.rule.stack_with_not_all_capabilities|
|message|data.rule.stack_with_not_all_capabilities_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudformation_stack' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_CFR_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** A CloudFormation stack needs certain capability, It is recommended to configure the stack with capabilities not all capabilities (*) should be configured. This will give the stack unlimited access.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_cloudformation_stack']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
