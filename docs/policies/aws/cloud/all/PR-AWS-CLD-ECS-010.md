



# Master Test ID: PR-AWS-CLD-ECS-010


Master Snapshot Id: ['TEST_ECS_01']

type: rego

rule: [file(ecs.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ECS-010|
|eval: |data.rule.ecs_assign_public_ip|
|message: |data.rule.ecs_assign_public_ip_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html#cfn-ecs-service-enableexecutecommand' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ECS_010.py|


severity: Medium

title: Ensure that ECS Service and Task Set network configuration disallows the assignment of public IPs

description: Ensure that the ecs service and Task Set Network has set [AssignPublicIp/assign_public_ip] property is set to DISABLED else an Actor can exfiltrate data by associating ECS resources with non-ADATUM resources  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['ecs']|



[file(ecs.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecs.rego
