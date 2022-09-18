



# Title: AWS ECS task definition resource limits not set.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ECS-005

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ECS-005|
|eval|data.rule.ecs_resource_limit|
|message|data.rule.ecs_resource_limit_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ECS_005.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It is recommended that resource limits are set for AWS ECS task definition. Please make sure attributes 'Cpu' or 'Memory' exists and its value is not set to 0 under 'TaskDefinition' or 'ContainerDefinitions'.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ecs::taskdefinition']


[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego
