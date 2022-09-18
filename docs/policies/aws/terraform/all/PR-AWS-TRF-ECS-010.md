



# Title: Ensure that ECS Service and Task Set network configuration disallows the assignment of public IPs


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ECS-010

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ECS-010|
|eval|data.rule.ecs_assign_public_ip|
|message|data.rule.ecs_assign_public_ip_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service#network_configuration' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ECS_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure that the ecs service and Task Set Network has set [AssignPublicIp/assign_public_ip] property is set to DISABLED else an Actor can exfiltrate data by associating ECS resources with non-ADATUM resources  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_ecs_service']


[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego
