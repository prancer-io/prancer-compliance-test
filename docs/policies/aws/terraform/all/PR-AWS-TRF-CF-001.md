



# Title: AWS CloudFront Distributions with Field-Level Encryption not enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-CF-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([cloudfront.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-CF-001|
|eval|data.rule.cf_default_cache|
|message|data.rule.cf_default_cache_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_CF_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies CloudFront distributions for which field-level encryption is not enabled. Field-level encryption adds an additional layer of security along with HTTPS which protects specific data throughout system processing so that only certain applications can see it.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_cloudfront_distribution']


[cloudfront.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/cloudfront.rego
