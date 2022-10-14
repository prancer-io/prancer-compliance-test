



# Title: Ensure an IAM policy is defined with the stack.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-CFR-004

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-CFR-004|
|eval|data.rule.role_arn_exist|
|message|data.rule.role_arn_exist_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudformation_stack' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_CFR_004.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Stack policy protects resources from accidental updates, the policy included resources which shouldn't be updated during the template provisioning process.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_cloudformation_stack']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
