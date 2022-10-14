



# Title: Ensure that public facing ELB has WAF attached


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ELB-024

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ELB-024|
|eval|data.rule.elb_waf_enabled|
|message|data.rule.elb_waf_enabled_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#aws-resource-elasticloadbalancingv2-loadbalancer-syntax' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ELB_024.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** his policy checks the usage of a WAF with Internet facing ELB. AWS WAF is a web application firewall service that lets you monitor web requests and protect your web applications from malicious requests.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HITRUST', 'PCI DSS', 'NIST 800', 'MAS TRM']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::elasticloadbalancingv2::loadbalancer']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/elb.rego
