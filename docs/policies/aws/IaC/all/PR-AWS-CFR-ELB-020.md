



# Title: Ensure that AWS Ensure Elastic Load Balancer v2 (ELBv2) has deletion protection feature enabled.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ELB-020

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ELB-020|
|eval|data.rule.elb_deletion_protection|
|message|data.rule.elb_deletion_protection_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ELB_020.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy checks if the ELB is protected against accidental deletion by enabling deletion protection.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HITRUST', 'PCI DSS', 'NIST 800', 'MAS TRM']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::elasticloadbalancingv2::loadbalancer']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/elb.rego
