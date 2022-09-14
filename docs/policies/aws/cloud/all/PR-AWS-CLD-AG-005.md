



# Master Test ID: PR-AWS-CLD-AG-005


Master Snapshot Id: ['TEST_API_GATEWAY_01']

type: rego

rule: [file(api_gateway.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-AG-005|
|eval: |data.rule.gateway_tracing_enable|
|message: |data.rule.gateway_tracing_enable_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html#cfn-kms-key-enablekeyrotation' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_AG_005.py|


severity: Low

title: Ensure API Gateway has tracing enabled

description: With tracing enabled X-Ray can provide an end-to-end view of an entire HTTP request. You can use this to analyze latencies in APIs and their backend services  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['NIST 800']|
|service: |['api gateway']|



[file(api_gateway.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/api_gateway.rego
