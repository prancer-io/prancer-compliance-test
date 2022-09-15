



# Master Test ID: PR-AWS-CLD-KMS-001


***<font color="white">Master Snapshot Id:</font>*** ['TEST_KMS']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([kms.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-KMS-001|
|eval|data.rule.kms_key_rotation|
|message|data.rule.kms_key_rotation_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html#cfn-kms-key-enablekeyrotation' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_KMS_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** AWS Customer Master Key (CMK) rotation is not enabled

***<font color="white">Description:</font>*** This policy identifies Customer Master Keys (CMKs) that are not enabled with key rotation. AWS KMS (Key Management Service) allows customers to create master keys to encrypt sensitive data in different services. As a security best practice, it is important to rotate the keys periodically so that if the keys are compromised, the data in the underlying service is still secure with the new keys.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.2.0 (AWS)-2.8', 'CIS v1.3.0 (AWS)-3.8', 'CIS v1.4.0 (AWS)-3.8', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-EKM-01', 'CSA CCM v3.0.1-EKM-02', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 41", "CyberSecurity Law of the People's Republic of China-Article 43", "CyberSecurity Law of the People's Republic of China-Article 44", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.187', 'GDPR', 'GDPR-Article 25', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:10.g', 'ISO 27001', 'ISO 27001:2013-A.10.1.2', 'LGPD', 'MAS TRM', 'MAS TRM 2021-10.2.1', 'MAS TRM 2021-10.2.8', 'MAS TRM 2021-10.2.9', 'MITRE ATT&CK', 'MITRE ATT&CK v6.3-T1078', 'MITRE ATT&CK v6.3-T1098', 'MITRE ATT&CK v8.2-T1078', 'MLPS', 'MLPS 2.0-8.1.4.8', 'NIST 800', 'NIST 800-171 Rev1-3.13.10', 'NIST 800-53 Rev 5-Cryptographic Key Establishment and Management', 'NIST 800-53 Rev4-SC-12', 'NIST CSF', 'NIST CSF-PR.DS-1', 'NIST CSF-PR.DS-2', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.10', 'NIST SP 800-172-3.5.2e', 'PCI DSS v3.2.1-3.6.4', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.7.3', 'SOC 2', 'SOC 2-CC6.2', 'SOC 2-CC6.3']|
|service|['kms']|



[kms.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/kms.rego
