



# Master Test ID: PR-AWS-CLD-CT-007


***<font color="white">Master Snapshot Id:</font>*** ['TEST_CT_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([cloudtrail.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-CT-007|
|eval|data.rule.cloudtrail_logging_is_enabled|
|message|data.rule.cloudtrail_logging_is_enabled_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudtrail.html#CloudTrail.Client.describe_trails' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_CT_007.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure AWS CloudTrail logging is enabled.

***<font color="white">Description:</font>*** It identifies the CloudTrails in which logging is disabled. AWS CloudTrail is a service that enables governance, compliance, operational & risk auditing of the AWS account. It is a compliance and security best practice to turn on logging for CloudTrail across different regions to get a complete audit trail of activities across various services. NOTE: This policy will be triggered only when you have CloudTrail configured in your AWS account and logging is disabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'APRA', 'Brazilian Data Protection Law (LGPD)-Article 31', 'Brazilian Data Protection Law (LGPD)-Article 48', 'LGPD', 'CSA CCM v.4.0.1-LOG-05', 'CSA CCM v.4.0.1-LOG-06', 'CSA CCM v.4.0.1-LOG-08', 'CSA CCM v.4.0.1-LOG-13', 'CSA CCM', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.3.046', 'CMMC', 'HITRUST v.9.4.2-Control Reference:09.ab', 'HITRUST v.9.4.2-Control Reference:09.ac', 'HITRUST', 'ISO/IEC 27002:2013-12.4.1', 'ISO/IEC 27002:2013-12.4.3', 'ISO/IEC 27002:2013-12.4.4', 'ISO/IEC 27002:2013-16.1.1', 'ISO/IEC 27002', 'ISO/IEC 27017:2015-12.4.1', 'ISO/IEC 27017:2015-12.4.4', 'ISO/IEC 27017:2015-16.1.2', 'ISO/IEC 27017', 'MAS TRM 2021-7.5.7', 'MAS TRM', 'MITRE ATT&CK v10.0-T1562.008 - Impair Defenses:Disable Cloud Logs', 'MITRE ATT&CK', 'NIST 800-53 Rev 5-Vulnerability Monitoring and Scanning \| Review Historic Audit Logs', 'NIST 800-53 Rev4-RA-5 (8)', 'NIST 800', 'NIST CSF-PR.PT-1', 'NIST CSF', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.14.2e', 'NIST SP', 'PCI DSS v3.2.1-10.2.3', 'PCI DSS v3.2.1-10.6', 'PCI DSS', 'Risk Management in Technology (RMiT)-10.61', 'Risk Management in Technology (RMiT)-10.66', 'RMiT']|
|service|['cloudtrail']|



[cloudtrail.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/cloudtrail.rego
