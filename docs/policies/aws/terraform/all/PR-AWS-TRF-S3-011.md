



# Title: AWS S3 buckets are accessible to public


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-S3-011

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-S3-011|
|eval|data.rule.s3_public_access|
|message|data.rule.s3_public_access_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_S3_011.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'AWS Well-Architected Framework', 'AWS Well-Architected Framework-Data Protection', 'Brazilian Data Protection Law (LGPD)-Article 26', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-DSI-02', 'CSA CCM v3.0.1-IVS-06', 'CSA CCM v3.0.1-IVS-08', 'CSA CCM v3.0.1-MOS-13', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 30", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 45", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.1.004', 'GDPR', 'GDPR-Article 25', 'GDPR-Article 46', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:01.m', 'HITRUST CSF v9.3-Control Reference:01.n', 'HITRUST CSF v9.3-Control Reference:01.p', 'HITRUST CSF v9.3-Control Reference:05.j', 'HITRUST CSF v9.3-Control Reference:06.e', 'HITRUST CSF v9.3-Control Reference:09.z', 'ISO 27001', 'ISO 27001:2013-A.14.1.2', 'ISO 27001:2013-A.14.1.3', 'ISO 27001:2013-A.18.1.3', 'ISO 27001:2013-A.8.2.3', 'ISO 27001:2013-A.9.2.5', 'LGPD', 'MAS TRM', 'MAS TRM 2021-11.1.5', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1530 - Data from Cloud Storage Object', 'MITRE ATT&CK v6.3-T1530', 'MITRE ATT&CK v8.2-T1530', 'MLPS', 'MLPS 2.0-8.1.3.2', 'NIST 800', 'NIST 800-171 Rev1-3.1.9', 'NIST 800-171 Rev1-3.13.1', 'NIST 800-171 Rev1-3.13.2', 'NIST 800-171 Rev1-3.13.5', 'NIST 800-53 Rev 5-Boundary Protection', 'NIST 800-53 Rev 5-System Use Notification', 'NIST 800-53 Rev4-AC-8c', 'NIST 800-53 Rev4-SC-7b', 'NIST CSF', 'NIST CSF-DE.AE-1', 'NIST CSF-DE.CM-1', 'NIST CSF-ID.RA-5', 'NIST CSF-PR.AC-5', 'NIST CSF-PR.DS-5', 'NIST CSF-PR.PT-4', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.22', 'NIST SP 800-172-3.14.3e', 'PCI DSS v3.2.1-10.1', 'PCI DSS v3.2.1-7.1', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.1.4', 'RMiT', 'Risk Management in Technology (RMiT)-10.55', 'SOC 2', 'SOC 2-CC6.1', 'SOC 2-CC6.6', 'SOC 2-CC6.7']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_s3_bucket']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego
