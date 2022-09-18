



# Title: Ensure there are no undefined ECS task definition empty roles for ECS.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ECS-016

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ECS-016|
|eval|data.rule.no_ecs_task_definition_empty_roles|
|message|data.rule.no_ecs_task_definition_empty_roles_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html#aws-resource-ecs-taskdefinition--examples' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ECS_016.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks if the ECS container has a role attached. The task execution role grants the Amazon ECS container and Fargate agents permission to make AWS API calls on your behalf. The task execution IAM role is required depending on the requirements of your task.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'CMMC', 'HITRUST', 'LGPD', 'MAS TRM', 'PCI-DSS', 'NIST 800', 'NIST SP']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ecs::taskdefinition']


[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego
