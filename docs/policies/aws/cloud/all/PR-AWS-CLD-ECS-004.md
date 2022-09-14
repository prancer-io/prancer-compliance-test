



# Master Test ID: PR-AWS-CLD-ECS-004


Master Snapshot Id: ['TEST_ECS_03']

type: rego

rule: [file(ecs.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ECS-004|
|eval: |data.rule.ecs_root_filesystem|
|message: |data.rule.ecs_root_filesystem_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ECS_004.py|


severity: High

title: AWS ECS Task Definition readonlyRootFilesystem Not Enabled

description: It is recommended that readonlyRootFilesystem is enabled for AWS ECS task definition. Please make sure your 'ContainerDefinitions' template has 'ReadonlyRootFilesystem' and is set to 'true'.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34']|
|service: |['ecs']|



[file(ecs.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecs.rego
