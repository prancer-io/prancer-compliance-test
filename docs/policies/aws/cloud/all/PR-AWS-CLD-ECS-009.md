



# Master Test ID: PR-AWS-CLD-ECS-009


Master Snapshot Id: ['TEST_ECS_01']

type: rego

rule: [file(ecs.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ECS-009|
|eval: |data.rule.ecs_enable_execute_command|
|message: |data.rule.ecs_enable_execute_command_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html#cfn-ecs-service-enableexecutecommand' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ECS_009.py|


severity: High

title: Ensure ECS Services and Task Set EnableExecuteCommand property set to False

description: If the EnableExecuteCommand property is set to True on an ECS Service then any third person can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['ecs']|



[file(ecs.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecs.rego
