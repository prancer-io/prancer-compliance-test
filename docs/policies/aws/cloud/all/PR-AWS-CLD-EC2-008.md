



# Master Test ID: PR-AWS-CLD-EC2-008


***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC2_02']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EC2-008|
|eval|data.rule.ebs_snapshot_public_access|
|message|data.rule.ebs_snapshot_public_access_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_images' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EC2_008.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Ensure AWS EBS snapshots are not accessible to public

***<font color="white">Description:</font>*** This policy identifies EC2 EBS snapshots are accessible to the public. Amazon Elastic Block Store (Amazon EBS) provides persistent block storage volumes with Amazon EC2 instances in the AWS Cloud. If EBS snapshots are inadvertently shared to the public, any unauthorized user with AWS console access can gain access to the snapshots and gain access to sensitive data.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-DSI-02', 'CSA CCM v3.0.1-IVS-06', 'CSA CCM v3.0.1-IVS-08', 'CSA CCM v3.0.1-MOS-13', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 30", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 45", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.192', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.4.199', 'GDPR', 'GDPR-Article 25', 'GDPR-Article 46', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:01.m', 'HITRUST CSF v9.3-Control Reference:01.n', 'HITRUST CSF v9.3-Control Reference:01.p', 'HITRUST CSF v9.3-Control Reference:05.j', 'HITRUST CSF v9.3-Control Reference:06.e', 'HITRUST CSF v9.3-Control Reference:09.z', 'ISO 27001', 'ISO 27001:2013-A.14.1.2', 'ISO 27001:2013-A.14.1.3', 'ISO 27001:2013-A.18.1.3', 'ISO 27001:2013-A.8.2.3', 'LGPD', 'MAS TRM', 'MAS TRM 2021-11.1.5', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1190 - Exploit Public-Facing Application', 'MITRE ATT&CK v6.3-T1005', 'MITRE ATT&CK v6.3-T1190', 'MITRE ATT&CK v8.2-T1190', 'MLPS', 'MLPS 2.0-8.1.3.2', 'NIST 800', 'NIST 800-171 Rev1-3.1.9', 'NIST 800-171 Rev1-3.13.1', 'NIST 800-171 Rev1-3.13.2', 'NIST 800-171 Rev1-3.13.5', 'NIST 800-53 Rev 5-Boundary Protection', 'NIST 800-53 Rev 5-System Use Notification', 'NIST 800-53 Rev4-AC-8c', 'NIST 800-53 Rev4-SC-7b', 'NIST CSF', 'NIST CSF-DE.AE-1', 'NIST CSF-DE.CM-1', 'NIST CSF-ID.RA-5', 'NIST CSF-PR.AC-5', 'NIST CSF-PR.DS-5', 'NIST CSF-PR.PT-4', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.22', 'NIST SP 800-172-3.14.3e', 'PCI DSS v3.2.1-7.1', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.1.4', 'RMiT', 'Risk Management in Technology (RMiT)-10.55', 'SOC 2', 'SOC 2-CC6.1', 'SOC 2-CC6.6', 'SOC 2-CC6.7']|
|service|['ec2']|



[ec2.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ec2.rego
