



# Title: Ensure Internet facing Classic ELB is not in use.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ELB-022

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ELB-022|
|eval|data.rule.elb_internet_facing_load_balancer|
|message|data.rule.elb_internet_facing_load_balancer_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elb' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ELB_022.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy checks if classic LB is being used in the environment for internet facing applications.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HITRUST', 'PCI DSS', 'NIST 800', 'MAS TRM']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_lb']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/elb.rego
