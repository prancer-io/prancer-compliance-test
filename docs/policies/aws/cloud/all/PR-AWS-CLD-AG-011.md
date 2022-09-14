



# Master Test ID: PR-AWS-CLD-AG-011


Master Snapshot Id: ['TEST_API_GATEWAY_04', 'TEST_ACM']

type: rego

rule: [file(api_gateway.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-AG-011|
|eval: |data.rule.api_gateway_gs_managed_acm|
|message: |data.rule.api_gateway_gs_managed_acm_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/apigateway.html#APIGateway.Client.get_domain_name' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_AG_011.py|


severity: High

title: Ensure custom domain in AWS API Gateway has GS-managed ACM certificate associated.

description: It checks for certificate details for the custom domain created for API gateway. Certificate are created in AWS ACM and can be selected for AWS Services for data in transit encryption.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['NIST 800', 'GDPR', 'CIS', 'ISO 27001', 'LGPD', 'HITRUST', 'HIPAA']|
|service: |['api gateway', 'acm']|



[file(api_gateway.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/api_gateway.rego
