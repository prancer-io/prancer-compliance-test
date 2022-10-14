



# Title: AWS ECS task definition resource limits not set.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ECS-005

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ECS-005|
|eval|data.rule.ecs_resource_limit|
|message|data.rule.ecs_resource_limit_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ECS_005.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It is recommended that resource limits are set for AWS ECS task definition. Please make sure attributes 'Cpu' or 'Memory' exists and its value is not set to 0 under 'TaskDefinition' or 'ContainerDefinitions'.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_ecs_task_definition']


[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego
