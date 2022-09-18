



# Title: VPC configurations on ECS Services must use either vended security groups


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ECS-013

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ECS-013|
|eval|data.rule.ecs_security_group|
|message|data.rule.ecs_security_group_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service#network_configuration' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ECS_013.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** ECS Service and ECS TaskSet resources set a SecurityGroup in the network_configuration. else Actor can exfiltrate data by associating ECS resources with non-ADATUM resources.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_ecs_service']


[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego
