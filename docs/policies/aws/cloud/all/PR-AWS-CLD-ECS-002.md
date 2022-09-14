



# Master Test ID: PR-AWS-CLD-ECS-002


Master Snapshot Id: ['TEST_ECS_03']

type: rego

rule: [file(ecs.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ECS-002|
|eval: |data.rule.ecs_exec|
|message: |data.rule.ecs_exec_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ECS_002.py|


severity: Medium

title: AWS ECS/Fargate task definition execution IAM Role not found

description: The execution IAM Role is required by tasks to pull container images and publish container logs to Amazon CloudWatch on your behalf. This policy generates an alert if a task execution role is not found in your task definition.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['HITRUST', 'GDPR', 'NIST 800', 'PCI DSS', 'CSA-CCM', 'ISO 27001']|
|service: |['ecs']|



[file(ecs.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecs.rego
