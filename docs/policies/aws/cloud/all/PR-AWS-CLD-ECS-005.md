



# Master Test ID: PR-AWS-CLD-ECS-005


Master Snapshot Id: ['TEST_ECS_03']

type: rego

rule: [file(ecs.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ECS-005|
|eval: |data.rule.ecs_resource_limit|
|message: |data.rule.ecs_resource_limit_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ECS_005.py|


severity: High

title: AWS ECS task definition resource limits not set.

description: It is recommended that resource limits are set for AWS ECS task definition. Please make sure attributes 'Cpu' or 'Memory' exists and its value is not set to 0 under 'TaskDefinition' or 'ContainerDefinitions'.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['ecs']|



[file(ecs.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecs.rego
