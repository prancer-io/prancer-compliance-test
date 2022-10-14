



# Title: Ensure Cloudformation rollback is disabled.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-CFR-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-CFR-003|
|eval|data.rule.cloudFormation_rollback_is_disabled|
|message|data.rule.cloudFormation_rollback_is_disabled_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudformation_stack' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_CFR_003.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It checks the stack rollback setting, in case of a failure do not rollback the entire stack. We can use change sets run the stack again, after fixing the template. Resources which are already provisioned won't be re-created.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_cloudformation_stack']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
