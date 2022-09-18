



# Title: Ensure the ELBv2 ListenerCertificate ListenerArn value is defined


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ELB-014

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ELB-014|
|eval|data.rule.elb_certificate_listner_arn|
|message|data.rule.elb_certificate_listner_arn_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenercertificate.html|
|remediationFunction|PR_AWS_CFR_ELB_014.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure the ELBv2 ListenerCertificate ListenerArn value is defined, else an Actor can provide access to CA to non-ADATUM principals.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::elasticloadbalancingv2::listenercertificate']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/elb.rego
