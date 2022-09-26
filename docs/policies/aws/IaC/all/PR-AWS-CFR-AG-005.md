



# Title: Ensure API Gateway has tracing enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-AG-005

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([api_gateway.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-AG-005|
|eval|data.rule.gateway_tracing_enable|
|message|data.rule.gateway_tracing_enable_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_AG_005.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** With tracing enabled X-Ray can provide an end-to-end view of an entire HTTP request. You can use this to analyze latencies in APIs and their backend services  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::apigateway::stage']


[api_gateway.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/api_gateway.rego
