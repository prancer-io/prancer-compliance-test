



# Title: Ensure AWS CloudTrail is enabled on the account.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-CT-006

***<font color="white">Master Snapshot Id:</font>*** ['TEST_CT_02']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([cloudtrail.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-CT-006|
|eval|data.rule.cloudtrail_is_enabled|
|message|data.rule.cloudtrail_is_enabled_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudtrail.html#CloudTrail.Client.describe_trails' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_CT_006.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** AWS CloudTrail is a service that enables governance, compliance, operational & risk auditing of the AWS account. It is a compliance and security best practice to turn on CloudTrail to get a complete audit trail of activities across various services.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 31', 'Brazilian Data Protection Law (LGPD)-Article 48', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.3.046', 'GDPR', 'GDPR-Article 30', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:01.p', 'HITRUST CSF v9.3-Control Reference:09.ad', 'HITRUST CSF v9.3-Control Reference:09.ae', 'ISO 27001', 'ISO 27001:2013-A.14.1.3', 'LGPD', 'MAS TRM', 'MAS TRM 2021-7.5.7', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1562.008 - Impair Defenses:Disable Cloud Logs', 'MITRE ATT&CK v6.3-T1078', 'MITRE ATT&CK v6.3-T1098', 'MITRE ATT&CK v8.2-T1078', 'NIST 800', 'NIST 800-171 Rev1-3.3.1', 'NIST 800-171 Rev1-3.3.2', 'NIST 800-53 Rev 5-Audit Record Generation \| System-wide and Time-correlated Audit Trail', 'NIST 800-53 Rev4-AU-12 (1)', 'NIST CSF', 'NIST CSF-DE.AE-1', 'NIST CSF-DE.CM-7', 'NIST CSF-PR.PT-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.4.2e', 'PCI DSS v3.2.1-10.1', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.1.4', 'RMiT', 'Risk Management in Technology (RMiT)-10.61', 'Risk Management in Technology (RMiT)-10.66', 'SOC 2', 'SOC 2-CC8.1']|
|service|['cloudtrail']|



[cloudtrail.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/cloudtrail.rego
