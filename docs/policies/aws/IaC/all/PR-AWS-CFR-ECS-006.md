



# Title: AWS ECS task definition logging not enabled. or only valid option for LogDriver is 'awslogs'


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ECS-006

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ECS-006|
|eval|data.rule.ecs_logging|
|message|data.rule.ecs_logging_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ECS_006.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It is recommended that logging is enabled for AWS ECS task definition. Please make sure your 'TaskDefinition' template has 'LogConfiguration' and 'LogDriver' configured.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ecs::taskdefinition']


[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego
