



# Title: Ensure that ECS services and Task Sets are launched as Fargate type


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ECS-011

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ECS-011|
|eval|data.rule.ecs_launch_type|
|message|data.rule.ecs_launch_type_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service#launch_type' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ECS_011.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure that ECS services and Task Sets are launched as Fargate type else Actor can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_ecs_service']


[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego
