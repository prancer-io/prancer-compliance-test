



# Title: Ensure AWS API Gateway uses TLS 1.2 in transit


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-AG-009

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([api_gateway.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-AG-009|
|eval|data.rule.api_gateway_uses_specific_tls_version|
|message|data.rule.api_gateway_uses_specific_tls_version_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-domainname.html#cfn-apigateway-domainname-securitypolicy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_AG_009.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It identifies if data is encrypted in transit using TLS1.2 for the traffic that API gateway sends.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800', 'GDPR', 'CIS', 'ISO 27001', 'LGPD', 'HITRUST', 'HIPAA']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::apigateway::domainname']


[api_gateway.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/api_gateway.rego
