



# Title: Ensure AWS API Gateway uses TLS 1.2 in transit


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-AG-009

***<font color="white">Master Snapshot Id:</font>*** ['TEST_API_GATEWAY_04']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([api_gateway.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-AG-009|
|eval|data.rule.api_gateway_uses_specific_tls_version|
|message|data.rule.api_gateway_uses_specific_tls_version_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/apigateway.html#APIGateway.Client.get_domain_name' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_AG_009.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It identifies if data is encrypted in transit using TLS1.2 for the traffic that API gateway sends.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['NIST 800', 'GDPR', 'CIS', 'ISO 27001', 'LGPD', 'HITRUST', 'HIPAA']|
|service|['api gateway']|



[api_gateway.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/api_gateway.rego
