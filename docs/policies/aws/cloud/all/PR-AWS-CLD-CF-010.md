



# Master Test ID: PR-AWS-CLD-CF-010


Master Snapshot Id: ['TEST_CF']

type: rego

rule: [file(cloudfront.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-CF-010|
|eval: |data.rule.cf_s3_origin|
|message: |data.rule.cf_s3_origin_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudfront.html#CloudFront.Client.get_distribution' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_CF_010.py|


severity: Medium

title: AWS Cloudfront Distribution with S3 have Origin Access set to disabled

description: This policy identifies the AWS CloudFront distributions which are utilizing S3 bucket and have Origin Access Disabled. The origin access identity feature should be enabled for all your AWS CloudFront CDN distributions in order to restrict any direct access to your objects through Amazon S3 URLs.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Secure access management', 'Brazilian Data Protection Law (LGPD)-Article 34', 'CMMC', 'CSA CCM', 'CSA CCM v.4.0.1-AIS-01', 'CSA CCM v.4.0.1-AIS-02', 'CSA CCM v.4.0.1-AIS-04', 'CSA CCM v.4.0.1-CCC-01', 'CSA CCM v.4.0.1-GRC-03', 'CSA CCM v.4.0.1-IVS-04', 'CSA CCM v.4.0.1-UEM-06', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-CM.2.062', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:10.a', 'ISO/IEC 27002', 'ISO/IEC 27002:2013-12.1.2', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.2.1', 'ISO/IEC 27002:2013-14.2.2', 'ISO/IEC 27017', 'ISO/IEC 27017:2015-12.1.2', 'ISO/IEC 27017:2015-14.1.1', 'ISO/IEC 27017:2015-14.1.2', 'ISO/IEC 27017:2015-14.2.1', 'ISO/IEC 27017:2015-14.2.5', 'ISO/IEC 27017:2015-5.1.1', 'ISO/IEC 27018', 'ISO/IEC 27018:2019-12.1.2', 'LGPD', 'MAS TRM', 'MAS TRM 2021-7.2.1', 'MAS TRM 2021-7.2.2', 'NIST 800', 'NIST 800-53 Rev 5-Boundary Protection \| Connections to Public Networks', 'NIST 800-53 Rev4-CA-3 (4)', 'NIST CSF', 'NIST CSF-PR.IP-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.4.2', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'PCI DSS v3.2.1-6.3', 'PCI-DSS']|
|service: |['cloudfront']|



[file(cloudfront.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/cloudfront.rego
