



# Title: Ensure API Gateway has tracing enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-AG-005

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([api_gateway.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-AG-005|
|eval|data.rule.gateway_tracing_enable|
|message|data.rule.gateway_tracing_enable_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_stage' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_AG_005.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** With tracing enabled X-Ray can provide an end-to-end view of an entire HTTP request. You can use this to analyze latencies in APIs and their backend services  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_api_gateway_stage']


[api_gateway.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/api_gateway.rego
