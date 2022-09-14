



# Master Test ID: PR-AWS-CLD-AG-004


Master Snapshot Id: ['TEST_API_GATEWAY_01']

type: rego

rule: [file(api_gateway.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-AG-004|
|eval: |data.rule.gateway_logging_enable|
|message: |data.rule.gateway_logging_enable_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html#cfn-kms-key-enablekeyrotation' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_AG_004.py|


severity: Low

title: Ensure that API Gateway has enabled access logging

description: Enabling the custom access logging option in API Gateway allows delivery of custom logs to CloudWatch Logs, which can be analyzed using CloudWatch Logs Insights. Using custom domain names in Amazon API Gateway allows insights into requests sent to each custom domain name.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['NIST 800', 'GDPR']|
|service: |['api gateway']|



[file(api_gateway.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/api_gateway.rego
