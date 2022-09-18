



# Title: Ensure AWS Config includes global resources types (IAM).


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-CFG-004

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-CFG-004|
|eval|data.rule.config_includes_global_resources|
|message|data.rule.config_includes_global_resources_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_recorder#include_global_resource_types' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_CFG_004.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It checks that global resource types are included in AWS Config.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_config_configuration_recorder']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
