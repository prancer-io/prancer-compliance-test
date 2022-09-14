



# Master Test ID: PR-AWS-CLD-ECS-012


Master Snapshot Id: ['TEST_ECS_01']

type: rego

rule: [file(ecs.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ECS-012|
|eval: |data.rule.ecs_subnet|
|message: |data.rule.ecs_subnet_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-service-awsvpcconfiguration.html#cfn-ecs-service-awsvpcconfiguration-subnets' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ECS_012.py|


severity: Medium

title: Value(s) of subnets attached to aws ecs service or taskset AwsVpcConfiguration resources are vended

description: Value(s) of subnets attached to aws ecs service or taskset AwsVpcConfiguration resources are vended else Actor can exfiltrate data by associating ECS resources with non-ADATUM resources.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['ecs']|



[file(ecs.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecs.rego
