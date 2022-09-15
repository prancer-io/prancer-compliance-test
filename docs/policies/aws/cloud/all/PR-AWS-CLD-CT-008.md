



# Master Test ID: PR-AWS-CLD-CT-008


***<font color="white">Master Snapshot Id:</font>*** ['TEST_CT_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([cloudtrail.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-CT-008|
|eval|data.rule.cloudtrail_with_cloudwatch|
|message|data.rule.cloudtrail_with_cloudwatch_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudtrail.html#CloudTrail.Client.describe_trails' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_CT_008.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure AWS CloudTrail logs is integrated with CloudWatch for all regions.

***<font color="white">Description:</font>*** It identifies the Cloudtrails which is not integrated with cloudwatch for all regions. CloudTrail uses Amazon S3 for log file storage and delivery, so log files are stored durably. In addition to capturing CloudTrail logs within a specified S3 bucket for long term analysis, realtime analysis can be performed by configuring CloudTrail to send logs to CloudWatch Logs. For a trail that is enabled in all regions in an account, CloudTrail sends log files from all those regions to a CloudWatch Logs log group. It is recommended that CloudTrail logs be sent to CloudWatch Logs.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'LGPD', 'CCPA', 'CSA CCM', "CyberSecurity Law of the People's Republic of China", 'CMMC', 'GDPR', 'HITRUST', 'ISO 27001', 'MAS TRM', 'MITRE ATT&CK', 'MLPS', 'NIST 800', 'NIST CSF', 'NIST SP', 'PCI DSS', 'RMiT', 'SOC 2', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 31', 'Brazilian Data Protection Law (LGPD)-Article 48', 'CCPA 2018-1798.150(a)(1)', 'CSA CCM v3.0.1-AAC-01', 'CSA CCM v3.0.1-AAC-02', "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.3.046', 'GDPR-Article 30', 'HITRUST CSF v9.3-Control Reference:01.p', 'HITRUST CSF v9.3-Control Reference:05.h', 'HITRUST CSF v9.3-Control Reference:06.g', 'HITRUST CSF v9.3-Control Reference:06.h', 'HITRUST CSF v9.3-Control Reference:09.ad', 'HITRUST CSF v9.3-Control Reference:09.ae', 'HITRUST CSF v9.3-Control Reference:10.m', 'HITRUST CSF v9.3-Control Reference:11.b', 'HITRUST v.9.4.2-Control Reference:09.ab', 'HITRUST v.9.4.2-Control Reference:09.ac', 'ISO 27001:2013-A.14.1.3', 'ISO 27001:2013-A.9.2.5', 'MAS TRM 2021-7.5.7', 'MITRE ATT&CK v6.3-T1535', 'MITRE ATT&CK v8.2-T1535', 'MLPS 2.0-8.1.5.4', 'NIST 800-171 Rev1-3.3.1', 'NIST 800-171 Rev1-3.3.2', 'NIST 800-53 Rev 5-Audit Record Generation \| System-wide and Time-correlated Audit Trail', 'NIST 800-53 Rev 5-Continuous Monitoring', 'NIST 800-53 Rev4-AU-12 (1)', 'NIST 800-53 Rev4-CA-7e', 'NIST CSF-DE.AE-1', 'NIST CSF-DE.AE-3', 'NIST CSF-DE.CM-1', 'NIST CSF-DE.CM-2', 'NIST CSF-DE.CM-3', 'NIST CSF-DE.CM-6', 'NIST CSF-DE.CM-7', 'NIST CSF-DE.DP-1', 'NIST CSF-DE.DP-2', 'NIST CSF-DE.DP-3', 'NIST CSF-DE.DP-4', 'NIST CSF-DE.DP-5', 'NIST CSF-ID.RA-1', 'NIST CSF-PR.IP-7', 'NIST CSF-PR.IP-8', 'NIST CSF-PR.PT-1', 'NIST CSF-RS.CO-3', 'NIST CSF-RS.MI-3', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.14.2e', 'PCI DSS v3.2.1-10.2.3', 'PCI DSS v3.2.1-10.6', 'PIPEDA-4.1.4', 'Risk Management in Technology (RMiT)-10.61', 'Risk Management in Technology (RMiT)-10.66', 'SOC 2-CC8.1']|
|service|['cloudtrail']|



[cloudtrail.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/cloudtrail.rego
