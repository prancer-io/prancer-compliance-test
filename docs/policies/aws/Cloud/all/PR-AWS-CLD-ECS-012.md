



# Title: Value(s) of subnets attached to aws ecs service or taskset AwsVpcConfiguration resources are vended


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-ECS-012

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ECS_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ECS-012|
|eval|data.rule.ecs_subnet|
|message|data.rule.ecs_subnet_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-service-awsvpcconfiguration.html#cfn-ecs-service-awsvpcconfiguration-subnets' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ECS_012.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Value(s) of subnets attached to aws ecs service or taskset AwsVpcConfiguration resources are vended else Actor can exfiltrate data by associating ECS resources with non-ADATUM resources.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['ecs']|



[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecs.rego
