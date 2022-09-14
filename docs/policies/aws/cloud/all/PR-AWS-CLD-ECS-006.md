



# Master Test ID: PR-AWS-CLD-ECS-006


Master Snapshot Id: ['TEST_ECS_03']

type: rego

rule: [file(ecs.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ECS-006|
|eval: |data.rule.ecs_logging|
|message: |data.rule.ecs_logging_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ECS_006.py|


severity: High

title: AWS ECS task definition logging not enabled. or only valid option for LogDriver is 'awslogs'

description: It is recommended that logging is enabled for AWS ECS task definition. Please make sure your 'TaskDefinition' template has 'LogConfiguration' and 'LogDriver' configured.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['NIST 800']|
|service: |['ecs']|



[file(ecs.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecs.rego
