



# Title: Ensure that Listeners redirect using only the HTTPS protocol.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ELB-027

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ELB-027|
|eval|data.rule.elb_listner_redirect_protocol|
|message|data.rule.elb_listner_redirect_protocol_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ELB_027.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Listeners that use default actions including RedirectConfigs must set the protocol to HTTPS on those RedirectConfigs.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::elasticloadbalancingv2::listener']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/elb.rego
