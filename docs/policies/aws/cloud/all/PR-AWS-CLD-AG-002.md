



# Master Test ID: PR-AWS-CLD-AG-002


Master Snapshot Id: ['TEST_API_GATEWAY_02']

type: rego

rule: [file(api_gateway.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-AG-002|
|eval: |data.rule.gateway_validate_parameter|
|message: |data.rule.gateway_validate_parameter_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html#cfn-kms-key-enablekeyrotation' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_AG_002.py|


severity: Medium

title: AWS API gateway request parameter is not validated

description: This policy identifies the AWS API gateways for with the request parameters are not validated. It is recommended to validate the request parameters in the URI, query string, and headers of an incoming request to focus on the validation efforts specific to your application.
  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['Best Practice']|
|service: |['api gateway']|



[file(api_gateway.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/api_gateway.rego
