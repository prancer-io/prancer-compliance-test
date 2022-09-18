



# Title: Ensure that a log driver has been configured for each ECS task definition.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ECS-017

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ECS-017|
|eval|data.rule.ecs_log_driver|
|message|data.rule.ecs_log_driver_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition#container_definitions' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ECS_017.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It checks if log information from the containers running on ECS are send out to CloudWatch logs for monitoring.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'CMMC', 'HITRUST', 'LGPD', 'MAS TRM', 'PCI-DSS', 'NIST 800', 'NIST SP']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_ecs_task_definition']


[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego
