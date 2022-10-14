



# Title: Ensure LoadBalancer TargetGroup protocol values are limited to HTTPS


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ELB-019

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ELB-019|
|eval|data.rule.elb_protocol|
|message|data.rule.elb_protocol_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ELB_019.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The only allowed protocol value for LoadBalancer TargetGroups is HTTPS, though the property is ignored if the target type is lambda.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_lb_target_group']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/elb.rego
