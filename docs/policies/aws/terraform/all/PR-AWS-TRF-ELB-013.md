



# Title: Ensure that Application Load Balancer drops HTTP headers


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ELB-013

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ELB-013|
|eval|data.rule.elb_drop_invalid_header|
|message|data.rule.elb_drop_invalid_header_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/load_balancer_listener_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ELB_013.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Checks if rule evaluates AWS Application Load Balancers (ALB) to ensure they are configured to drop http headers. The rule is NON_COMPLIANT if the value of routing.http.drop_invalid_header_fields.enabled is set to false  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_load_balancer_policy']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/elb.rego
