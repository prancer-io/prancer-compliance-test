



# Master Test ID: PR-AWS-CLD-AG-001


Master Snapshot Id: ['TEST_API_GATEWAY_01']

type: rego

rule: [file(api_gateway.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-AG-001|
|eval: |data.rule.gateway_private|
|message: |data.rule.gateway_private_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html#cfn-kms-key-enablekeyrotation' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_AG_001.py|


severity: High

title: API Gateway should have API Endpoint type as private and not exposed to internet

description: Ensure that the Api endpoint type in api gateway is set to private and Is not exposed to the public internet  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['MAS', 'SOC2', 'ISO 27001', 'NIST', 'CIS', 'GDPR', 'PCI DSS', 'GDPR', 'HIPAA']|
|service: |['api gateway']|



[file(api_gateway.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/api_gateway.rego
