



# Title: Ensure AWS API Gateway uses TLS 1.2 in transit


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-AG-009

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([api_gateway.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-AG-009|
|eval|data.rule.api_gateway_uses_specific_tls_version|
|message|data.rule.api_gateway_uses_specific_tls_version_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_domain_name#security_policy' target='_blank'>here</a> |
|remediationFunction|PR_AWS_TRF_AG_009.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It identifies if data is encrypted in transit using TLS1.2 for the traffic that API gateway sends.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800', 'GDPR', 'CIS', 'ISO 27001', 'LGPD', 'HITRUST', 'HIPAA']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_api_gateway_domain_name']


[api_gateway.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/api_gateway.rego
