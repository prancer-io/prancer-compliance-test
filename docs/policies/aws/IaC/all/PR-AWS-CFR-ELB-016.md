



# Title: Ensure one of Subnets or SubnetMappings is defined for loadbalancer


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ELB-016

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ELB-016|
|eval|data.rule.elb_subnet|
|message|data.rule.elb_subnet_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-subnetmapping.html#cfn-elasticloadbalancingv2-loadbalancer-subnetmapping-subnetid|
|remediationFunction|PR_AWS_CFR_ELB_016.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure one of Subnets or SubnetMappings is defined for loadbalancer  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::elasticloadbalancingv2::loadbalancer']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/elb.rego
