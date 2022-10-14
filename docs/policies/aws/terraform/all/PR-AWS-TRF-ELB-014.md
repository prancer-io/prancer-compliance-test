



# Title: Ensure the ELBv2 ListenerCertificate listener_arn value is defined


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ELB-014

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ELB-014|
|eval|data.rule.elb_certificate_listner_arn|
|message|data.rule.elb_certificate_listner_arn_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener_certificate' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ELB_014.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure the ELBv2 ListenerCertificate listener_arn value is defined, else an Actor can provide access to CA to non-ADATUM principals.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_lb_listener_certificate']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/elb.rego
