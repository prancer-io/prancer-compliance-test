



# Master Test ID: PR-AWS-CLD-ECS-011


Master Snapshot Id: ['TEST_ECS_01']

type: rego

rule: [file(ecs.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ECS-011|
|eval: |data.rule.ecs_launch_type|
|message: |data.rule.ecs_launch_type_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html#cfn-ecs-service-launchtype' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ECS_011.py|


severity: Medium

title: Ensure that ECS services and Task Sets are launched as Fargate type

description: Ensure that ECS services and Task Sets are launched as Fargate type else Actor can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['ecs']|



[file(ecs.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecs.rego
