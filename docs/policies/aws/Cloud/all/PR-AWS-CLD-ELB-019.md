



# Title: Ensure LoadBalancer TargetGroup Protocol values are limited to HTTPS


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-ELB-019

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ELB_03']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ELB-019|
|eval|data.rule.elb_protocol|
|message|data.rule.elb_protocol_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-loadbalancerattributes.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ELB_019.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The only allowed Protocol value for LoadBalancer TargetGroups is HTTPS, though the property is ignored if the target type is lambda.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'NIST 800']|
|service|['elb']|



[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elb.rego
