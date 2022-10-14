



# Title: AWS API gateway request authorization is not set


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-AG-003

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([api_gateway.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-AG-003|
|eval|data.rule.gateway_request_authorizer|
|message|data.rule.gateway_request_authorizer_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-restapi-endpointconfiguration.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_AG_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies AWS API Gateways of protocol type REST for which the request authorisation is not set. The method request for API gateways takes the client input that is passed to the back end through the integration request. It is recommended to add authorization type to each of the method to add a layer of protection.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::apigateway::authorizer']


[api_gateway.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/api_gateway.rego
