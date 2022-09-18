



# Title: Ensure EFS volumes in ECS task definitions have encryption in transit enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-ECS-007

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ECS_03']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ECS-007|
|eval|data.rule.ecs_transit_enabled|
|message|data.rule.ecs_transit_enabled_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-taskdefinition-efsvolumeconfiguration.html#cfn-ecs-taskdefinition-efsvolumeconfiguration-transitencryption' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ECS_007.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** ECS task definitions that have volumes using EFS configuration should explicitly enable in transit encryption to prevent the risk of data loss due to interception.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['ecs']|



[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecs.rego
