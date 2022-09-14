



# Master Test ID: PR-AWS-CLD-ELB-024


Master Snapshot Id: ['TEST_ELB_07']

type: rego

rule: [file(elb.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ELB-024|
|eval: |data.rule.elb_waf_enabled|
|message: |data.rule.elb_waf_enabled_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html#ElasticLoadBalancingv2.Client.describe_load_balancer_attributes' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ELB_024.py|


severity: Medium

title: Ensure that public facing ELB has WAF attached

description: This policy checks the usage of a WAF with Internet facing ELB. AWS WAF is a web application firewall service that lets you monitor web requests and protect your web applications from malicious requests.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['HITRUST', 'PCI DSS', 'NIST 800', 'MAS TRM']|
|service: |['elb']|



[file(elb.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elb.rego
