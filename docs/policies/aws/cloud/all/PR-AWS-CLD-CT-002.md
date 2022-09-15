



# Master Test ID: PR-AWS-CLD-CT-002


***<font color="white">Master Snapshot Id:</font>*** ['TEST_CT_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([cloudtrail.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-CT-002|
|eval|data.rule.ct_log_validation|
|message|data.rule.ct_log_validation_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html#cfn-kms-key-enablekeyrotation' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_CT_002.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** AWS CloudTrail log validation is not enabled in all regions

***<font color="white">Description:</font>*** This policy identifies AWS CloudTrails in which log validation is not enabled in all regions. CloudTrail log file validation creates a diAWSally signed digest file containing a hash of each log that CloudTrail writes to S3. These digest files can be used to determine whether a log file was modified after CloudTrail delivered the log. It is recommended that file validation be enabled on all CloudTrails.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Data protection', 'AWS Foundational Security Best Practices standard-Logging', 'Brazilian Data Protection Law (LGPD)-Article 31', 'Brazilian Data Protection Law (LGPD)-Article 48', 'CIS', 'CIS v1.2.0 (AWS)-2.2', 'CIS v1.3.0 (AWS)-3.2', 'CIS v1.4.0 (AWS)-3.2', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-IAM-01', 'CSA CCM v3.0.1-IVS-01', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.3.046', 'GDPR', 'GDPR-Article 25', 'GDPR-Article 32', 'HIPAA', 'HIPAA-164.312(b)', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:09.ac', 'HITRUST v.9.4.2-Control Reference:10.a', 'ISO 27001', 'ISO 27001:2013-A.12.4.3', 'ISO 27001:2013-A.14.1.3', 'LGPD', 'MAS TRM', 'MAS TRM 2021-7.5.7', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1535 - Unused/Unsupported Cloud Regions', 'MITRE ATT&CK v6.3-T1535', 'MITRE ATT&CK v8.2-T1535', 'NIST 800', 'NIST 800-171 Rev1-3.3.8', 'NIST 800-53 Rev 5-Protection of Audit Information \| Cryptographic Protection', 'NIST 800-53 Rev4-AU-9 (3)', 'NIST CSF', 'NIST CSF-DE.AE-1', 'NIST CSF-PR.DS-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'NZISM', 'New Zealand Information Security Manual (NZISM v3.4)-16.6', 'New Zealand Information Security Manual (NZISM v3.4)-17.1', 'PCI DSS v3.2.1-6.3', 'PCI-DSS', 'RMiT', 'Risk Management in Technology (RMiT)-10.61', 'Risk Management in Technology (RMiT)-10.66', 'SOC 2', 'SOC 2-CC8.1']|
|service|['cloudtrail']|



[cloudtrail.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/cloudtrail.rego
