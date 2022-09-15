



# Master Test ID: PR-AWS-CLD-EC2-001


***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC2_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EC2-001|
|eval|data.rule.ec2_iam_role|
|message|data.rule.ec2_iam_role_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EC2_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** AWS EC2 Instance IAM Role not enabled

***<font color="white">Description:</font>*** AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-14', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.2.0 (AWS)-1.19', 'CIS v1.3.0 (AWS)-1.18', 'CIS v1.4.0 (AWS)-1.18', 'CMMC', 'CSA CCM', 'CSA CCM v.4.0.1-DSP-17', 'CSA CCM v.4.0.1-IAM-04', 'CSA CCM v.4.0.1-IAM-05', 'CSA CCM v.4.0.1-IAM-09', 'CSA CCM v.4.0.1-IAM-16', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 30", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 41", "CyberSecurity Law of the People's Republic of China-Article 43", "CyberSecurity Law of the People's Republic of China-Article 44", "CyberSecurity Law of the People's Republic of China-Article 45", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.2.007', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:01.c', 'ISO/IEC 27002', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-18.1.4', 'ISO/IEC 27002:2013-6.1.2', 'ISO/IEC 27002:2013-9.1.1', 'ISO/IEC 27002:2013-9.1.2', 'ISO/IEC 27002:2013-9.2.3', 'ISO/IEC 27002:2013-9.2.5', 'ISO/IEC 27017', 'ISO/IEC 27017:2015-9.2.3', 'ISO/IEC 27017:2015-9.2.5', 'ISO/IEC 27018', 'ISO/IEC 27018:2019-9.2.3', 'ISO/IEC 27018:2019-9.2.5', 'LGPD', 'MAS TRM', 'MAS TRM 2021-9.1.1', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1098 - Account Manipulation', 'MITRE ATT&CK v6.3-T1098', 'MITRE ATT&CK v8.2-T1098', 'MLPS', 'MLPS 2.0-8.2.4.1', 'NIST 800', 'NIST 800-53 Rev 5-Access Enforcement \| Role-based Access Control', 'NIST 800-53 Rev4-AC-3 (7)', 'NIST CSF', 'NIST CSF-PR.AC-4', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.5', 'NIST SP 800-172-3.1.2e', 'PCI DSS v3.2.1-7.1', 'PCI DSS v3.2.1-7.1.2', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.7.3', 'RMiT', 'Risk Management in Technology (RMiT)-10.55']|
|service|['ec2']|



[ec2.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ec2.rego
