



# Title: Ensure Internet facing Classic ELBV2 is not in use


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-ELB-023

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ELB_06']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ELB-023|
|eval|data.rule.elb2_internet_facing_load_balancer|
|message|data.rule.elb2_internet_facing_load_balancer_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-protocol' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ELB_023.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy checks if ELB v2 is being used in the environment.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['HITRUST', 'PCI DSS', 'NIST 800', 'MAS TRM']|
|service|['elb']|



[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elb.rego
