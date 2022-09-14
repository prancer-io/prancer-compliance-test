



# Master Test ID: PR-AWS-CLD-CF-004


Master Snapshot Id: ['TEST_CF']

type: rego

rule: [file(cloudfront.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-CF-004|
|eval: |data.rule.cf_https_only|
|message: |data.rule.cf_https_only_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_CF_004.py|


severity: High

title: AWS CloudFront origin protocol policy does not enforce HTTPS-only

description: It is a best security practice to enforce HTTPS-only traffic between a CloudFront distribution and the origin. This policy scans for any deviations from this practice and returns the results.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CIS', 'CIS AWS 3 Tier Web Architecture Benchmark v.1.0.0-1.17', 'CMMC', 'CSA CCM', 'CSA CCM v.4.0.1-CEK-03', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-IVS-03', 'CSA CCM v.4.0.1-UEM-11', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 40", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.185', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:09.s', 'ISO/IEC 27002', 'ISO/IEC 27002:2013-10.1.1', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.3.1', 'ISO/IEC 27002:2013-13.1.1', 'ISO/IEC 27002:2013-13.1.2', 'ISO/IEC 27002:2013-13.1.3', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.1.3', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-8.3.1', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017', 'ISO/IEC 27017:2015-10.1.1', 'ISO/IEC 27017:2015-10.1.2', 'ISO/IEC 27017:2015-6.1.1', 'ISO/IEC 27018', 'ISO/IEC 27018:2019-10.1.2', 'ISO/IEC 27018:2019-12.3.1', 'LGPD', 'MAS TRM', 'MAS TRM 2021-11.1.1', 'MAS TRM 2021-14.1.2', 'MLPS', 'MLPS 2.0-8.1.4.8', 'NIST 800', 'NIST 800-53 Rev 5-Transmission Confidentiality and Integrity \| Cryptographic Protection', 'NIST 800-53 Rev4-SC-8 (1)', 'NIST CSF', 'NIST CSF-PR.DS-2', 'NIST CSF-PR.DS-5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.8', 'NIST SP 800-172-3.1.3e', 'PCI DSS v3.2.1-2.3', 'PCI DSS v3.2.1-4.1', 'PCI-DSS', 'RMiT', 'Risk Management in Technology (RMiT)-10.68']|
|service: |['cloudfront']|



[file(cloudfront.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/cloudfront.rego
