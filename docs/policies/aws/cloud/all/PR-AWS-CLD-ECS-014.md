



# Master Test ID: PR-AWS-CLD-ECS-014


Master Snapshot Id: ['TEST_ECS_03']

type: rego

rule: [file(ecs.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ECS-014|
|eval: |data.rule.ecs_network_mode|
|message: |data.rule.ecs_network_mode_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html#cfn-ecs-taskdefinition-networkmode' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ECS_014.py|


severity: Medium

title: Ensure that ECS Task Definition have their network mode property set to awsvpc

description: Ensure that ECS Task Definition have their network mode property set to awsvpc. else an Actor can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['ecs']|



[file(ecs.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecs.rego
