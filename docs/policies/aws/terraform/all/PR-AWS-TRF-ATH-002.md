



# Title: Ensure Athena logging is enabled for athena workgroup.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ATH-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ATH-002|
|eval|data.rule.athena_logging_is_enabled|
|message|data.rule.athena_logging_is_enabled_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ATH_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks if logging is enabled for Athena to detect incidents, receive alerts when incidents occur, and respond to them. logs can be configured via CloudTrail, CloudWatch events and Quicksights for visualization.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_athena_workgroup']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
