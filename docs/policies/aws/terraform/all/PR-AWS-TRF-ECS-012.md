



# Title: Value(s) of subnets attached to aws ecs service subnets are vended


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ECS-012

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ECS-012|
|eval|data.rule.ecs_subnet|
|message|data.rule.ecs_subnet_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service#network_configuration' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ECS_012.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Value(s) of subnets attached to aws ecs service subnets are vended else Actor can exfiltrate data by associating ECS resources with non-ADATUM resources.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_ecs_service']


[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego
