



# Title: AWS ECS - Ensure Fargate task definition logging is enabled.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ECS-015

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ECS-015|
|eval|data.rule.ecs_fargate_task_definition_logging_is_enabled|
|message|data.rule.ecs_fargate_task_definition_logging_is_enabled_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition#container_definitions' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ECS_015.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks if the Fargate task definition created has an execution IAM role associated, the role defines the extent of access to other AWS Services.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'CMMC', 'HITRUST', 'LGPD', 'MAS TRM', 'PCI-DSS', 'NIST 800', 'NIST SP']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_ecs_task_definition']


[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego
