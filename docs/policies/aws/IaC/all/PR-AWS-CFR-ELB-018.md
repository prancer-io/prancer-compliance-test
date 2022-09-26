



# Title: Ensure all load balancers created are application load balancers


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ELB-018

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ELB-018|
|eval|data.rule.elb_type|
|message|data.rule.elb_type_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-type|
|remediationFunction|PR_AWS_CFR_ELB_018.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure the value of Type for each LoadBalancer resource is application or the Type is not set, since it defaults to application  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::elasticloadbalancingv2::loadbalancer']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/elb.rego
