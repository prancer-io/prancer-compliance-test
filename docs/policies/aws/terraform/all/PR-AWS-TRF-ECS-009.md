



# Title: Ensure ECS Services and Task Set enable_execute_command property set to False


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ECS-009

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ECS-009|
|eval|data.rule.ecs_enable_execute_command|
|message|data.rule.ecs_enable_execute_command_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service#enable_execute_command' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ECS_009.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** If the enable_execute_command property is set to True on an ECS Service then any third person can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_ecs_service']


[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego
