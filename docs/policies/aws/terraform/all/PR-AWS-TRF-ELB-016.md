



# Title: Ensure one of subnets or subnet_mapping is defined for loadbalancer


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ELB-016

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ELB-016|
|eval|data.rule.elb_subnet|
|message|data.rule.elb_subnet_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-subnetmapping.html#cfn-elasticloadbalancingv2-loadbalancer-subnetmapping-subnetid' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ELB_016.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure one of subnets or subnet_mapping is defined for loadbalancer  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_lb']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/elb.rego
