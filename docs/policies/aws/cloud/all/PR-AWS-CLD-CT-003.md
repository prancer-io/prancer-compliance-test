



# Master Test ID: PR-AWS-CLD-CT-003


***<font color="white">Master Snapshot Id:</font>*** ['TEST_CT_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([cloudtrail.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-CT-003|
|eval|data.rule.ct_master_key|
|message|data.rule.ct_master_key_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html#cfn-kms-key-enablekeyrotation' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_CT_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** AWS CloudTrail logs are not encrypted using Customer Master Keys (CMKs)

***<font color="white">Description:</font>*** Checks to ensure that CloudTrail logs are encrypted. AWS CloudTrail is a service that enables governance, compliance, operational risk auditing of the AWS account. It is a compliance and security best practice to encrypt the CloudTrail data since it may contain sensitive information.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Data protection', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CIS', 'CIS v1.2.0 (AWS)-2.7', 'CIS v1.3.0 (AWS)-3.7', 'CIS v1.4.0 (AWS)-3.7', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-IAM-01', 'CSA CCM v3.0.1-IVS-01', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 30", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 40", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.177', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.185', 'GDPR', 'GDPR-Article 25', 'GDPR-Article 32', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:09.ac', 'HITRUST v.9.4.2-Control Reference:06.d', 'HITRUST v.9.4.2-Control Reference:09.s', 'ISO 27001', 'ISO 27001:2013-A.10.1.2', 'ISO 27001:2013-A.12.4.2', 'ISO 27001:2013-A.14.1.3', 'ISO 27001:2013-A.9.2.5', 'LGPD', 'MAS TRM', 'MAS TRM 2021-11.1.1', 'MAS TRM 2021-11.1.3', 'MLPS', 'MLPS 2.0-8.1.4.8', 'NIST 800', 'NIST 800-171 Rev1-3.3.8', 'NIST 800-53 Rev 5-Protection of Audit Information \| Cryptographic Protection', 'NIST 800-53 Rev4-AU-9 (3)', 'NIST CSF', 'NIST CSF-DE.AE-1', 'NIST CSF-PR.DS-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.16', 'NIST SP 800-172-3.1.3e', 'NZISM', 'New Zealand Information Security Manual (NZISM v3.4)-17.1', 'PCI DSS v3.2.1-3.4.1', 'PCI DSS v3.2.1-4.1', 'PCI-DSS', 'RMiT', 'Risk Management in Technology (RMiT)-10.51', 'Risk Management in Technology (RMiT)-10.68', 'SOC 2', 'SOC 2-CC8.1']|
|service|['cloudtrail']|



[cloudtrail.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/cloudtrail.rego
