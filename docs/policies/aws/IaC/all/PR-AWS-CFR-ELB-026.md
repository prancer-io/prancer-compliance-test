



# Title: Ensure that ELB Listener is limited to approved actions.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ELB-026

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ELB-026|
|eval|data.rule.elb_default_action|
|message|data.rule.elb_default_action_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ELB_026.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure the AWS::ElasticLoadBalancingV2::Listener Action Type is limited to: 'fixed-response', 'forward', 'redirect'  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::elasticloadbalancingv2::listener']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/elb.rego
