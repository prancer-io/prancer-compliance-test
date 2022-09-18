



# Title: Ensure ECS Services and Task Set EnableExecuteCommand property set to False


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ECS-009

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ECS-009|
|eval|data.rule.ecs_enable_execute_command|
|message|data.rule.ecs_enable_execute_command_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html#cfn-ecs-service-enableexecutecommand' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ECS_008.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** If the EnableExecuteCommand property is set to True on an ECS Service then any third person can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ecs::service', 'aws::ecs::taskset']


[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego
