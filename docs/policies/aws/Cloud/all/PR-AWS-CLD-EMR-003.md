



# Title: AWS EMR cluster is not configured with CSE CMK for data at rest encryption (Amazon S3 with EMRFS)


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-EMR-003

***<font color="white">Master Snapshot Id:</font>*** ['TEST_EMR']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([emr.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EMR-003|
|eval|data.rule.emr_s3_encryption|
|message|data.rule.emr_s3_encryption_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EMR_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies EMR clusters which are not configured with Client Side Encryption with Customer Master Keys(CSE CMK) for data at rest encryption of Amazon S3 with EMRFS. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your EMR cluster and ensure full control over your data.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 34', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CMMC', 'CSA CCM', 'CSA CCM v.4.0.1-CEK-03', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-UEM-11', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 30", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 40", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.177', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.191', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:06.d', 'HITRUST v.9.4.2-Control Reference:09.s', 'ISO/IEC 27002', 'ISO/IEC 27002:2013-10.1.1', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.3.1', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.1.3', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-8.3.1', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017', 'ISO/IEC 27017:2015-10.1.1', 'ISO/IEC 27017:2015-10.1.2', 'ISO/IEC 27017:2015-6.1.1', 'ISO/IEC 27018', 'ISO/IEC 27018:2019-10.1.2', 'ISO/IEC 27018:2019-12.3.1', 'LGPD', 'MAS TRM', 'MAS TRM 2021-11.1.1', 'MAS TRM 2021-11.1.3', 'MLPS', 'MLPS 2.0-8.1.4.8', 'NIST 800', 'NIST 800-53 Rev 5-Protection of Information at Rest', 'NIST 800-53 Rev 5-Remote Access \| Protection of Confidentiality and Integrity Using Encryption', 'NIST 800-53 Rev4-AC-17 (2)', 'NIST 800-53 Rev4-SC-28', 'NIST CSF', 'NIST CSF-PR.DS-1', 'NIST CSF-PR.DS-5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.16', 'NIST SP 800-172-3.1.3e', 'PCI DSS v3.2.1-3.4.1', 'PCI DSS v3.2.1-4.1', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.7.3', 'RMiT', 'Risk Management in Technology (RMiT)-10.51', 'Risk Management in Technology (RMiT)-10.68', 'Risk Management in Technology (RMiT)-11.15']|
|service|['emr']|



[emr.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/emr.rego
