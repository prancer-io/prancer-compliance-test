



# Title: VPC configurations on ECS Services and TaskSets must use either vended security groups


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ECS-013

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ECS-013|
|eval|data.rule.ecs_security_group|
|message|data.rule.ecs_security_group_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-service-awsvpcconfiguration.html#cfn-ecs-service-awsvpcconfiguration-securitygroups' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ECS_013.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** ECS Service and ECS TaskSet resources set a SecurityGroup in the AwsvpcConfiguration. else Actor can exfiltrate data by associating ECS resources with non-ADATUM resources.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ecs::service', 'aws::ecs::taskset']


[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego
