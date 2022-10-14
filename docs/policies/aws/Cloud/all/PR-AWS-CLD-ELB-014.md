



# Title: Ensure the ELBv2 ListenerCertificate ListenerArn value is defined


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-ELB-014

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ELB_02']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ELB-014|
|eval|data.rule.elb_certificate_listner_arn|
|message|data.rule.elb_certificate_listner_arn_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenercertificate.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ELB_014.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure the ELBv2 ListenerCertificate ListenerArn value is defined, else an Actor can provide access to CA to non-ADATUM principals.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['Best Practice']|
|service|['elb']|



[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elb.rego
