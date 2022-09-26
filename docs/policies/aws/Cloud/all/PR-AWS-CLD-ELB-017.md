



# Title: Ensure LoadBalancer scheme is set to internal and not internet-facing


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-ELB-017

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ELB_06']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ELB-017|
|eval|data.rule.elb_scheme|
|message|data.rule.elb_scheme_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ELB_017.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** LoadBalancer scheme must be explicitly set to internal, else an Actor can allow access to ADATUM information through the misconfiguration of an ELB resource  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['HITRUST', 'HITRUST v.9.4.2-Control Reference:01.c', 'HITRUST v.9.4.2-Control Reference:09.m', 'MAS TRM', 'MAS TRM 2021-11.1.5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.22', 'NIST SP 800-172-3.14.3e', 'PCI DSS v3.2.1-1.3', 'PCI DSS v3.2.1-7.1', 'PCI-DSS']|
|service|['elb']|



[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elb.rego
