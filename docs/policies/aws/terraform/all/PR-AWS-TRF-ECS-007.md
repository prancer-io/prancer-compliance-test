



# Title: Ensure EFS volumes in ECS task definitions have encryption in transit enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ECS-007

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ECS-007|
|eval|data.rule.ecs_transit_enabled|
|message|data.rule.ecs_transit_enabled_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ECS_007.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** ECS task definitions that have volumes using EFS configuration should explicitly enable in transit encryption to prevent the risk of data loss due to interception.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_ecs_task_definition']


[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego
