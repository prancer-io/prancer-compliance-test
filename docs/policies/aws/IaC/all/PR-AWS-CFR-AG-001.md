



# Title: API Gateway should have API Endpoint type as private and not exposed to internet


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-AG-001

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([api_gateway.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-AG-001|
|eval|data.rule.gateway_private|
|message|data.rule.gateway_private_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-restapi-endpointconfiguration.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_AG_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure that the Api endpoint type in api gateway is set to private and Is not exposed to the public internet  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['MAS', 'SOC2', 'ISO 27001', 'NIST', 'CIS', 'GDPR', 'PCI DSS', 'GDPR', 'HIPAA']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::apigateway::restapi']


[api_gateway.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/api_gateway.rego
