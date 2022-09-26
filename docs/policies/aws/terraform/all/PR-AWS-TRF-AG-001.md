



# Title: API Gateway should have API Endpoint type as private and not exposed to internet


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-AG-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([api_gateway.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-AG-001|
|eval|data.rule.gateway_private|
|message|data.rule.gateway_private_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_rest_api' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_AG_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure that the Api endpoint type in api gateway is set to private and Is not exposed to the public internet  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['MAS', 'SOC2', 'ISO 27001', 'NIST', 'CIS', 'GDPR', 'PCI DSS', 'GDPR', 'HIPAA']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_api_gateway_rest_api']


[api_gateway.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/api_gateway.rego
