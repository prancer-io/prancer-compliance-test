



# Title: Ensure content encoding is enabled for API Gateway.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-AG-010

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([api_gateway.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-AG-010|
|eval|data.rule.api_gateway_content_encoding_is_enabled|
|message|data.rule.api_gateway_content_encoding_is_enabled_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-restapi.html#cfn-apigateway-restapi-minimumcompressionsize' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_AG_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks if API Gateway allows client to call API with compressed payloads by using one of the supported content codings. This is useful in cases where you need to compress the method response payload.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800', 'GDPR', 'CIS', 'ISO 27001', 'LGPD', 'HITRUST', 'HIPAA']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::apigateway::restapi']


[api_gateway.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/api_gateway.rego
