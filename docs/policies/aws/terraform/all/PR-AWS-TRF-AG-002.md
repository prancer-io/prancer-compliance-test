



# Title: AWS API gateway request parameter is not validated


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-AG-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([api_gateway.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-AG-002|
|eval|data.rule.gateway_validate_parameter|
|message|data.rule.gateway_validate_parameter_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_request_validator' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_AG_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies the AWS API gateways for with the request parameters are not validated. It is recommended to validate the request parameters in the URI, query string, and headers of an incoming request to focus on the validation efforts specific to your application.
  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_api_gateway_request_validator']


[api_gateway.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/api_gateway.rego
