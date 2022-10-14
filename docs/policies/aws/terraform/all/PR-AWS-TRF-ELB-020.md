



# Title: Ensure that AWS Elastic Load Balancer v2 (ELBv2) has deletion protection feature enabled.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ELB-020

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ELB-020|
|eval|data.rule.elb_deletion_protection|
|message|data.rule.elb_deletion_protection_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ELB_020.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy checks if the ELB is protected against accidental deletion by enabling deletion protection.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HITRUST', 'PCI DSS', 'NIST 800', 'MAS TRM']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_lb']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/elb.rego
