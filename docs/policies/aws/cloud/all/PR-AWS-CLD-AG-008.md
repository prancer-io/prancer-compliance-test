



# Master Test ID: PR-AWS-CLD-AG-008


***<font color="white">Master Snapshot Id:</font>*** ['TEST_API_GATEWAY_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([api_gateway.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-AG-008|
|eval|data.rule.api_gateway_not_configured_with_firewall_v2|
|message|data.rule.api_gateway_not_configured_with_firewall_v2_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/apigateway.html#APIGateway.Client.get_stage' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_AG_008.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** AWS API Gateway REST API is not configured with AWS Web Application Firewall v2 (AWS WAFv2)

***<font color="white">Description:</font>*** AWS API Gateway REST API which is not configured with AWS Web Application Firewall. As a best practice, enable the AWS WAF service on API Gateway REST API to protect against application layer attacks. To block malicious requests to your API Gateway REST API, define the block criteria in the WAF web access control list (web ACL).  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['NIST 800', 'GDPR', 'CIS', 'ISO 27001', 'LGPD', 'HITRUST', 'HIPAA']|
|service|['api gateway']|



[api_gateway.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/api_gateway.rego
