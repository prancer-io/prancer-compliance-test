



# Master Test ID: PR-AWS-CLD-CF-001


Master Snapshot Id: ['TEST_CF']

type: rego

rule: [file(cloudfront.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-CF-001|
|eval: |data.rule.cf_default_cache|
|message: |data.rule.cf_default_cache_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_CF_001.py|


severity: Medium

title: AWS CloudFront Distributions with Field-Level Encryption not enabled

description: This policy identifies CloudFront distributions for which field-level encryption is not enabled. Field-level encryption adds an additional layer of security along with HTTPS which protects specific data throughout system processing so that only certain applications can see it.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['PCI DSS', 'GDPR', 'CSA CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF']|
|service: |['cloudfront']|



[file(cloudfront.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/cloudfront.rego
