



# Master Test ID: PR-AWS-CLD-SQS-002


Master Snapshot Id: ['TEST_SQS']

type: rego

rule: [file(sqs.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-SQS-002|
|eval: |data.rule.sqs_encrypt_key|
|message: |data.rule.sqs_encrypt_key_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_SQS_002.py|


severity: Medium

title: AWS SQS queue encryption using default KMS key instead of CMK

description: This policy identifies CloudFront web distributions which have a default SSL certificate to access CloudFront content. It is a best practice to use custom SSL Certificate to access CloudFront content. It gives you full control over the content data. custom SSL certificates also allow your users to access your content by using an alternate domain name. You can use a certificate stored in AWS Certificate Manager (ACM) or you can use a certificate stored in IAM.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Data protection', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CMMC', 'CSA CCM', 'CSA CCM v.4.0.1-CEK-03', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-IVS-03', 'CSA CCM v.4.0.1-UEM-11', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 30", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 40", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.177', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.185', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:06.d', 'HITRUST v.9.4.2-Control Reference:09.s', 'ISO/IEC 27002', 'ISO/IEC 27002:2013-10.1.1', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.3.1', 'ISO/IEC 27002:2013-13.1.1', 'ISO/IEC 27002:2013-13.1.2', 'ISO/IEC 27002:2013-13.1.3', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.1.3', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-8.3.1', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017', 'ISO/IEC 27017:2015-10.1.1', 'ISO/IEC 27017:2015-10.1.2', 'ISO/IEC 27017:2015-6.1.1', 'ISO/IEC 27018', 'ISO/IEC 27018:2019-10.1.2', 'ISO/IEC 27018:2019-12.3.1', 'LGPD', 'MAS TRM', 'MAS TRM 2021-11.1.1', 'MAS TRM 2021-11.1.3', 'MLPS', 'MLPS 2.0-8.1.4.8', 'NIST 800', 'NIST 800-53 Rev 5-Cryptographic Key Establishment and Management', 'NIST 800-53 Rev 5-Remote Access \| Protection of Confidentiality and Integrity Using Encryption', 'NIST 800-53 Rev 5-Transmission Confidentiality and Integrity \| Cryptographic Protection', 'NIST 800-53 Rev4-AC-17 (2)', 'NIST 800-53 Rev4-SC-12', 'NIST 800-53 Rev4-SC-8 (1)', 'NIST CSF', 'NIST CSF-PR.DS-2', 'NIST CSF-PR.DS-5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.8', 'NIST SP 800-172-3.1.3e', 'NZISM', 'New Zealand Information Security Manual (NZISM v3.4)-17.1', 'PCI DSS v3.2.1-3.4.1', 'PCI DSS v3.2.1-4.1', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.7.3', 'RMiT', 'Risk Management in Technology (RMiT)-10.51', 'Risk Management in Technology (RMiT)-10.68']|
|service: |['sqs']|



[file(sqs.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/sqs.rego
