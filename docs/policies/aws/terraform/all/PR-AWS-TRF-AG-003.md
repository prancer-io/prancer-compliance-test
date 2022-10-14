



# Title: AWS API gateway request authorization is not set


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-AG-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([api_gateway.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-AG-003|
|eval|data.rule.gateway_request_authorizer|
|message|data.rule.gateway_request_authorizer_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_authorizer' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_AG_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies AWS API Gateways of protocol type REST for which the request authorisation is not set. The method request for API gateways takes the client input that is passed to the back end through the integration request. It is recommended to add authorization type to each of the method to add a layer of protection.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_api_gateway_authorizer']


[api_gateway.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/api_gateway.rego
