



# Master Test ID: PR-AWS-CLD-AG-010


Master Snapshot Id: ['TEST_API_GATEWAY_02']

type: rego

rule: [file(api_gateway.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-AG-010|
|eval: |data.rule.api_gateway_content_encoding_is_enabled|
|message: |data.rule.api_gateway_content_encoding_is_enabled_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/apigateway.html#APIGateway.Client.get_rest_api' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_AG_010.py|


severity: Medium

title: Ensure content encoding is enabled for API Gateway.

description: It checks if API Gateway allows client to call API with compressed payloads by using one of the supported content codings. This is useful in cases where you need to compress the method response payload.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CMMC', 'CSA CCM', 'CSA CCM v.4.0.1-AIS-01', 'CSA CCM v.4.0.1-AIS-02', 'CSA CCM v.4.0.1-AIS-04', 'CSA CCM v.4.0.1-CCC-01', 'CSA CCM v.4.0.1-GRC-03', 'CSA CCM v.4.0.1-IVS-04', 'CSA CCM v.4.0.1-UEM-06', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-CM.2.062', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:10.a', 'ISO', 'ISO/IEC 27002:2013-12.1.2', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.2.1', 'ISO/IEC 27002:2013-14.2.2', 'ISO/IEC 27017:2015-12.1.2', 'ISO/IEC 27017:2015-14.1.1', 'ISO/IEC 27017:2015-14.1.2', 'ISO/IEC 27017:2015-14.2.1', 'ISO/IEC 27017:2015-14.2.5', 'ISO/IEC 27017:2015-5.1.1', 'ISO/IEC 27018:2019-12.1.2', 'LGPD', 'MAS TRM', 'MAS TRM 2021-7.2.1', 'MAS TRM 2021-7.2.2', 'NIST CSF', 'NIST CSF-PR.IP-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.4.2', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-6.3']|
|service: |['api gateway']|



[file(api_gateway.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/api_gateway.rego
