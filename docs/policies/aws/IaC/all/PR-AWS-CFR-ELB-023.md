



# Title: Ensure Internet facing ELBV2 is not in use.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ELB-023

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ELB-023|
|eval|data.rule.elb2_internet_facing_load_balancer|
|message|data.rule.elb2_internet_facing_load_balancer_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ELB_023.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy checks if ELB v2 is being used in the environment.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HITRUST', 'PCI DSS', 'NIST 800', 'MAS TRM']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::elasticloadbalancingv2::loadbalancer']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/elb.rego
