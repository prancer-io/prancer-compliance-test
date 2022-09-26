



# Title: Ensure all load balancers created are application load balancers


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ELB-018

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ELB-018|
|eval|data.rule.elb_type|
|message|data.rule.elb_type_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ELB_018.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure the value of Type for each LoadBalancer resource is application or the Type is not set, since it defaults to application  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_lb']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/elb.rego
