



# Title: Storage Accounts https based secure transfer should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-STR-003

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-STR-003|
|eval|data.rule.storage_secure|
|message|data.rule.storage_secure_err|
|remediationDescription|Make sure you are following the ARM template guidelines for storage accounts by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts' target='_blank'>here</a>. supportsHttpsTrafficOnly should be true|
|remediationFunction|PR_AZR_ARM_STR_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPS. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPS for custom domain names, this option is not applied when using a custom domain name.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-DP-4', 'Azure Security Benchmark (v3)-DP-3', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.1 (Azure)-3.1', 'CIS v1.2.0 (Azure)-3.1', 'CIS v1.3.0 (Azure)-3.1', 'CIS v1.3.1 (Azure)-3.1', 'CIS v1.4.0 (Azure)-3.1', 'CSA CCM', 'CSA CCM v3.0.1-CCC-04', 'CSA CCM v3.0.1-EKM-02', 'CSA CCM v3.0.1-EKM-03', 'CSA CCM v3.0.1-EKM-04', "CyberSecurity Law of the People's Republic of China-Article 40", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.185', 'GDPR-Article 25', 'GDPR-Article 32', 'HIPAA', 'HIPAA-164.312(e)(2)(ii)', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:01.j', 'HITRUST CSF v9.3-Control Reference:01.y', 'HITRUST CSF v9.3-Control Reference:05.i', 'HITRUST CSF v9.3-Control Reference:06.f', 'HITRUST CSF v9.3-Control Reference:09.s', 'HITRUST CSF v9.3-Control Reference:09.x', 'HITRUST CSF v9.3-Control Reference:10.f', 'ISO 27001:2013', 'ISO 27001:2013-A.10.1.2', 'ISO 27001:2013-A.14.1.2', 'ISO 27001:2013-A.18.1.3', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1530 - Data from Cloud Storage Object', 'MITRE ATT&CK v6.3-T1530', 'MITRE ATT&CK v8.2-T1530', 'NIST 800', 'NIST 800-53 Rev4-AC-17 (2)', 'NIST 800-53 Rev4-SC-13', 'NIST 800-53 Rev4-SI-7 (6)', 'NIST CSF', 'NIST CSF-PR.DS-1', 'NIST CSF-PR.DS-5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.8', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-4.1', 'PCI DSS v3.2.1-6.5.3', 'PIPEDA', 'PIPEDA-4.7.3', 'SOC 2', 'SOC 2-CC6.1']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.storage/storageaccounts']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/storageaccounts.rego
