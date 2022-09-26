



# Title: AWS ECS/Fargate task definition execution IAM Role not found


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ECS-002

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ECS-002|
|eval|data.rule.ecs_exec|
|message|data.rule.ecs_exec_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ECS_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The execution IAM Role is required by tasks to pull container images and publish container logs to Amazon CloudWatch on your behalf. This policy generates an alert if a task execution role is not found in your task definition.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HITRUST', 'GDPR', 'NIST 800', 'PCI-DSS', 'CSA-CCM', 'ISO 27001']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ecs::taskdefinition']


[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego
