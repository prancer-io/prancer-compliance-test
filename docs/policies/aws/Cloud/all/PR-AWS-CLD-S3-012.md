



# Title: AWS S3 buckets do not have server side encryption.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-S3-012

***<font color="white">Master Snapshot Id:</font>*** ['TEST_S3']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-S3-012|
|eval|data.rule.s3_encryption|
|message|data.rule.s3_encryption_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_S3_012.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Data protection', 'AWS Well-Architected Framework', 'AWS Well-Architected Framework-Data Protection', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS AWS 3 Tier Web Architecture Benchmark v.1.0.0-1.16', 'CIS v1.3.0 (AWS)-2.1.1', 'CIS v1.4.0 (AWS)-2.1.1', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-IAM-01', 'CSA CCM v3.0.1-IVS-01', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 30", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 40", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.177', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.185', 'GDPR', 'GDPR-Article 25', 'GDPR-Article 32', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:09.ac', 'HITRUST v.9.4.2-Control Reference:06.d', 'ISO 27001', 'ISO 27001:2013-A.14.1.3', 'ISO 27001:2013-A.18.1.3', 'LGPD', 'MAS TRM', 'MAS TRM 2021-11.1.1', 'MAS TRM 2021-11.1.3', 'MITRE ATT&CK', 'MITRE ATT&CK v6.3-T1530', 'MITRE ATT&CK v8.2-T1530', 'MLPS', 'MLPS 2.0-8.1.4.8', 'NIST 800', 'NIST 800-171 Rev1-3.3.8', 'NIST 800-53 Rev 5-Protection of Audit Information \| Cryptographic Protection', 'NIST 800-53 Rev4-AU-9 (3)', 'NIST CSF', 'NIST CSF-DE.AE-1', 'NIST CSF-PR.DS-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.22', 'NIST SP 800-172-3.1.3e', 'NZISM', 'New Zealand Information Security Manual (NZISM v3.4)-17.1', 'PCI DSS v3.2.1-3.4.1', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.7.3', 'RMiT', 'Risk Management in Technology (RMiT)-10.51', 'Risk Management in Technology (RMiT)-10.68', 'Risk Management in Technology (RMiT)-11.15', 'SOC 2', 'SOC 2-CC8.1']|
|service|['cloud']|



[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
