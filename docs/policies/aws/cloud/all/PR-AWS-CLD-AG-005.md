



# Master Test ID: PR-AWS-CLD-AG-005


***<font color="white">Master Snapshot Id:</font>*** ['TEST_API_GATEWAY_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([api_gateway.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-AG-005|
|eval|data.rule.gateway_tracing_enable|
|message|data.rule.gateway_tracing_enable_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html#cfn-kms-key-enablekeyrotation' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_AG_005.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** Ensure API Gateway has tracing enabled

***<font color="white">Description:</font>*** With tracing enabled X-Ray can provide an end-to-end view of an entire HTTP request. You can use this to analyze latencies in APIs and their backend services  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['NIST 800']|
|service|['api gateway']|



[api_gateway.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/api_gateway.rego
