



# Title: AWS Redshift database does not have audit logging enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-RSH-007

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([redshift.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-RSH-007|
|eval|data.rule.redshift_audit|
|message|data.rule.redshift_audit_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_RSH_007.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Audit logging is not enabled by default in Amazon Redshift. When you enable logging on your cluster, Amazon Redshift creates and uploads logs to Amazon S3 that capture data from the creation of the cluster to the present time.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Logging', 'Brazilian Data Protection Law (LGPD)-Article 31', 'Brazilian Data Protection Law (LGPD)-Article 48', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-CCC-04', 'CSA CCM v3.0.1-IAM-03', 'CSA CCM v3.0.1-IAM-06', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.3.046', 'Firmware, and Information Integrity', 'GDPR', 'GDPR-Article 30', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:01.p', 'HITRUST CSF v9.3-Control Reference:01.s', 'HITRUST CSF v9.3-Control Reference:06.i', 'HITRUST CSF v9.3-Control Reference:09.aa', 'HITRUST CSF v9.3-Control Reference:09.ab', 'HITRUST CSF v9.3-Control Reference:09.ad', 'HITRUST CSF v9.3-Control Reference:09.ae', 'HITRUST CSF v9.3-Control Reference:10.c', 'HITRUST CSF v9.3-Control Reference:10.k', 'HITRUST v.9.4.2-Control Reference:09.ab', 'HITRUST v.9.4.2-Control Reference:09.ac', 'ISO 27001', 'ISO 27001:2013-A.14.1.3', 'LGPD', 'MAS TRM', 'MAS TRM 2021-7.5.7', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1562.008 - Impair Defenses:Disable Cloud Logs', 'MLPS', 'MLPS 2.0-8.1.3.5', 'MLPS 2.0-8.1.4.3', 'NIST 800', 'NIST 800-171 Rev1-3.3.1', 'NIST 800-171 Rev1-3.3.2', 'NIST 800-171 Rev1-3.4.5', 'NIST 800-53 Rev 5-Access Restrictions for Change \| Automated Access Enforcement and Audit Records', 'NIST 800-53 Rev 5-Event Logging', 'NIST 800-53 Rev 5-Software', 'NIST 800-53 Rev4-AU-2a', 'NIST 800-53 Rev4-CM-5 (1)', 'NIST 800-53 Rev4-SI-7 (8)', 'NIST CSF', 'NIST CSF-PR.PT-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.14.2e', 'NZISM', 'New Zealand Information Security Manual (NZISM v3.4)-16.6', 'PCI DSS v3.2.1-10.2.3', 'PCI DSS v3.2.1-10.6', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.1.4', 'RMiT', 'Risk Management in Technology (RMiT)-10.61', 'Risk Management in Technology (RMiT)-10.66', 'SOC 2', 'SOC 2-CC6.1']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::redshift::cluster']


[redshift.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/redshift.rego
