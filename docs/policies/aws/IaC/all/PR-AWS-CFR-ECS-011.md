



# Title: Ensure that ECS services and Task Sets are launched as Fargate type


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ECS-011

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ECS-011|
|eval|data.rule.ecs_launch_type|
|message|data.rule.ecs_launch_type_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html#cfn-ecs-service-launchtype' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ECS_011.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure that ECS services and Task Sets are launched as Fargate type else Actor can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ecs::service', 'aws::ecs::taskset']


[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego
