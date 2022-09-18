



# Title: AWS ECS - Ensure Fargate task definition logging is enabled.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-ECS-015

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ECS_03']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ECS-015|
|eval|data.rule.ecs_fargate_task_definition_logging_is_enabled|
|message|data.rule.ecs_fargate_task_definition_logging_is_enabled_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs.html#ECS.Client.describe_task_definition' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ECS_015.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks if the Fargate task definition created has an execution IAM role associated, the role defines the extent of access to other AWS Services.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'CMMC', 'HITRUST', 'LGPD', 'MAS TRM', 'PCI-DSS', 'NIST 800', 'NIST SP']|
|service|['ecs']|



[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecs.rego
