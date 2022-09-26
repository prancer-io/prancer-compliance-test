



# Title: Ensure Internet facing ELBV2 is not in use.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ELB-023

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ELB-023|
|eval|data.rule.elb2_internet_facing_load_balancer|
|message|data.rule.elb2_internet_facing_load_balancer_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ELB_023.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy checks if ELB v2 is being used in the environment.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HITRUST', 'PCI DSS', 'NIST 800', 'MAS TRM']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_lb']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/elb.rego
