



# Title: Ensure that AWS ensure Gateway Load Balancer (GWLB) is not being used.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ELB-021

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ELB-021|
|eval|data.rule.elb_gateway_load_balancer|
|message|data.rule.elb_gateway_load_balancer_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ELB_021.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy checks if Gateway LB is being used or not.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HITRUST', 'PCI DSS', 'NIST 800', 'MAS TRM']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_lb']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/elb.rego
