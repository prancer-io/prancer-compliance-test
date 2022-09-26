



# Title: Ensure that public facing ELB has WAF attached


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ELB-024

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ELB-024|
|eval|data.rule.elb_waf_enabled|
|message|data.rule.elb_waf_enabled_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb#enable_waf_fail_open' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ELB_024.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy checks the usage of a WAF with Internet facing ELB. AWS WAF is a web application firewall service that lets you monitor web requests and protect your web applications from malicious requests.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HITRUST', 'PCI DSS', 'NIST 800', 'MAS TRM']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_lb']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/elb.rego
