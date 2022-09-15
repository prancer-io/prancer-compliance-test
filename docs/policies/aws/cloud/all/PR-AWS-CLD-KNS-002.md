



# Master Test ID: PR-AWS-CLD-KNS-002


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_11']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-KNS-002|
|eval|data.rule.kinesis_encryption_kms|
|message|data.rule.kinesis_encryption_kms_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kinesis-stream.html#aws-resource-kinesis-stream--examples' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_KNS_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** AWS Kinesis streams encryption using default KMS keys instead of Customer's Managed Master Keys

***<font color="white">Description:</font>*** This policy identifies the AWS Kinesis streams which are encrypted with default KMS keys and not with Master Keys managed by Customer. It is a best practice to use customer managed Master Keys to encrypt your Amazon Kinesis streams data. It gives you full control over the encrypted data.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-EKM-01', 'CSA CCM v3.0.1-EKM-02', 'CSA CCM v3.0.1-IAM-01', 'CSA CCM v3.0.1-IVS-01', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 30", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 40", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.177', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.185', 'GDPR', 'GDPR-Article 25', 'GDPR-Article 32', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:06.d', 'HITRUST CSF v9.3-Control Reference:09.ac', 'HITRUST CSF v9.3-Control Reference:10.g', 'HITRUST v.9.4.2-Control Reference:06.d', 'HITRUST v.9.4.2-Control Reference:09.s', 'ISO 27001', 'ISO 27001:2013-A.10.1.2', 'ISO 27001:2013-A.14.1.3', 'ISO 27001:2013-A.8.2.3', 'LGPD', 'MAS TRM', 'MAS TRM 2021-11.1.1', 'MAS TRM 2021-11.1.3', 'MLPS', 'MLPS 2.0-8.1.4.8', 'NIST 800', 'NIST 800-171 Rev1-3.13.10', 'NIST 800-171 Rev1-3.3.8', 'NIST 800-53 Rev 5-Cryptographic Key Establishment and Management', 'NIST 800-53 Rev 5-Protection of Audit Information \| Cryptographic Protection', 'NIST 800-53 Rev4-AU-9 (3)', 'NIST 800-53 Rev4-SC-12', 'NIST CSF', 'NIST CSF-DE.AE-1', 'NIST CSF-PR.DS-1', 'NIST CSF-PR.DS-2', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.8', 'NIST SP 800-172-3.1.3e', 'PCI DSS v3.2.1-3.4.1', 'PCI DSS v3.2.1-4.1', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.7.3', 'RMiT', 'Risk Management in Technology (RMiT)-10.51', 'Risk Management in Technology (RMiT)-10.68', 'SOC 2', 'SOC 2-CC6.2', 'SOC 2-CC6.3', 'SOC 2-CC8.1']|
|service|['kinesis']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
