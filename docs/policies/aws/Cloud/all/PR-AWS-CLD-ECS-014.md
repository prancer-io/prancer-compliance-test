



# Title: Ensure that ECS Task Definition have their network mode property set to awsvpc


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-ECS-014

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ECS_03']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ECS-014|
|eval|data.rule.ecs_network_mode|
|message|data.rule.ecs_network_mode_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html#cfn-ecs-taskdefinition-networkmode' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ECS_014.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure that ECS Task Definition have their network mode property set to awsvpc. else an Actor can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['ecs']|



[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecs.rego
