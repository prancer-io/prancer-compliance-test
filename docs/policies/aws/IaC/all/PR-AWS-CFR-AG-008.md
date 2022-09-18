



# Title: AWS API Gateway REST API is not configured with AWS Web Application Firewall v2 (AWS WAFv2)


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-AG-008

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([api_gateway.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-AG-008|
|eval|data.rule.api_gateway_not_configured_with_firewall_v2|
|message|data.rule.api_gateway_not_configured_with_firewall_v2_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_AG_008.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** AWS API Gateway REST API which is not configured with AWS Web Application Firewall. As a best practice, enable the AWS WAF service on API Gateway REST API to protect against application layer attacks. To block malicious requests to your API Gateway REST API, define the block criteria in the WAF web access control list (web ACL).  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800', 'GDPR', 'CIS', 'ISO 27001', 'LGPD', 'HITRUST', 'HIPAA']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::apigateway::stage', 'aws::wafregional::webaclassociation']


[api_gateway.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/api_gateway.rego
