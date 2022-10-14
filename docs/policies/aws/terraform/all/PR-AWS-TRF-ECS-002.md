



# Title: AWS ECS/Fargate task definition execution IAM Role not found


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ECS-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ECS-002|
|eval|data.rule.ecs_exec|
|message|data.rule.ecs_exec_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ECS_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The execution IAM Role is required by tasks to pull container images and publish container logs to Amazon CloudWatch on your behalf. This policy generates an alert if a task execution role is not found in your task definition.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HITRUST', 'GDPR', 'NIST 800', 'PCI-DSS', 'CSA-CCM', 'ISO 27001']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_ecs_task_definition']


[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego
