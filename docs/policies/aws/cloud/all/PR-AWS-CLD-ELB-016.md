



# Master Test ID: PR-AWS-CLD-ELB-016


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ELB_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ELB-016|
|eval|data.rule.elb_subnet|
|message|data.rule.elb_subnet_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-subnetmapping.html#cfn-elasticloadbalancingv2-loadbalancer-subnetmapping-subnetid' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ELB_016.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure one of Subnets or SubnetMappings is defined for loadbalancer

***<font color="white">Description:</font>*** Ensure one of Subnets or SubnetMappings is defined for loadbalancer  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['NIST 800']|
|service|['elb']|



[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elb.rego
