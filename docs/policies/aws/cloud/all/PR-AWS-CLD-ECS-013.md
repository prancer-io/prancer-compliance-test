



# Master Test ID: PR-AWS-CLD-ECS-013


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ECS_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ECS-013|
|eval|data.rule.ecs_security_group|
|message|data.rule.ecs_security_group_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-service-awsvpcconfiguration.html#cfn-ecs-service-awsvpcconfiguration-securitygroups' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ECS_013.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** VPC configurations on ECS Services and TaskSets must use either vended security groups

***<font color="white">Description:</font>*** ECS Service and ECS TaskSet resources set a SecurityGroup in the AwsvpcConfiguration. else Actor can exfiltrate data by associating ECS resources with non-ADATUM resources.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['ecs']|



[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecs.rego
