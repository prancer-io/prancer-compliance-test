



# Title: Ensure to enable enforce_workgroup_configuration for athena workgroup


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ATH-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ATH-001|
|eval|data.rule.athena_encryption_disabling_prevent|
|message|data.rule.athena_encryption_disabling_prevent_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ATH_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Athena workgroups support the ability for clients to override configuration options, including encryption requirements. This setting should be disabled to enforce encryption mandates  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_athena_workgroup']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
