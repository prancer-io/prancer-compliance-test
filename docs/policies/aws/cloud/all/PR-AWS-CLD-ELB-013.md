



# Master Test ID: PR-AWS-CLD-ELB-013


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ELB_05']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ELB-013|
|eval|data.rule.elb_drop_invalid_header|
|message|data.rule.elb_drop_invalid_header_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-loadbalancerattributes.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ELB_013.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure that Application Load Balancer drops HTTP headers

***<font color="white">Description:</font>*** Checks if rule evaluates AWS Application Load Balancers (ALB) to ensure they are configured to drop http headers. The rule is NON_COMPLIANT if the value of routing.http.drop_invalid_header_fields.enabled is set to false  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['Best Practice']|
|service|['elb']|



[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elb.rego
