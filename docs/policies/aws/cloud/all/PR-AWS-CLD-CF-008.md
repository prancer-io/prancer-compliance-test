



# Master Test ID: PR-AWS-CLD-CF-008


***<font color="white">Master Snapshot Id:</font>*** ['TEST_CF']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([cloudfront.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-CF-008|
|eval|data.rule.cf_default_ssl|
|message|data.rule.cf_default_ssl_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_CF_008.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** AWS CloudFront web distribution with default SSL certificate

***<font color="white">Description:</font>*** This policy identifies CloudFront web distributions which have a default SSL certificate to access CloudFront content. It is a best practice to use custom SSL Certificate to access CloudFront content. It gives you full control over the content data. custom SSL certificates also allow your users to access your content by using an alternate domain name. You can use a certificate stored in AWS Certificate Manager (ACM) or you can use a certificate stored in IAM.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Data protection', 'Brazilian Data Protection Law (LGPD)-Article 46', 'CMMC', 'CSA CCM', 'CSA CCM v.4.0.1-CEK-03', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-IVS-03', 'CSA CCM v.4.0.1-UEM-11', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 40", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.2.007', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.4.032', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:01.d', 'HITRUST v.9.4.2-Control Reference:01.r', 'ISO/IEC 27002', 'ISO/IEC 27002:2013-10.1.1', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.3.1', 'ISO/IEC 27002:2013-13.1.1', 'ISO/IEC 27002:2013-13.1.2', 'ISO/IEC 27002:2013-13.1.3', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.1.3', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-8.3.1', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017', 'ISO/IEC 27017:2015-10.1.1', 'ISO/IEC 27017:2015-10.1.2', 'ISO/IEC 27017:2015-6.1.1', 'ISO/IEC 27018', 'ISO/IEC 27018:2019-10.1.2', 'ISO/IEC 27018:2019-12.3.1', 'LGPD', 'MAS TRM', 'MAS TRM 2021-7.2.1', 'MAS TRM 2021-7.2.2', 'MLPS', 'MLPS 2.0-8.1.2.2', 'NIST 800', 'NIST 800-53 Rev 5-Transmission Confidentiality and Integrity \| Cryptographic Protection', 'NIST 800-53 Rev4-SC-8 (1)', 'NIST CSF', 'NIST CSF-PR.DS-2', 'NIST CSF-PR.DS-5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.8', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'NZISM', 'New Zealand Information Security Manual (NZISM v3.4)-17.4', 'PCI DSS v3.2.1-2.1', 'PCI-DSS', 'RMiT', 'Risk Management in Technology (RMiT)-10.68']|
|service|['cloudfront']|



[cloudfront.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/cloudfront.rego
