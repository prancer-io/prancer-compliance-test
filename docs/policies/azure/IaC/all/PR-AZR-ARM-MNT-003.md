



# Title: Azure Load Balancer diagnostics logs should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-MNT-003

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([diagnosticsettings.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-MNT-003|
|eval|data.rule.log_lbs|
|message|data.rule.log_lbs_err|
|remediationDescription|Make sure you are following the ARM template guidelines for SQL Server by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings' target='_blank'>here</a>. Make sure to enable diagnostics settings for load balancers|
|remediationFunction|PR_AZR_ARM_MNT_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure Load Balancers provide different types of logs alert events, health probe, metrics to help you manage and troubleshoot issues. This policy identifies Azure Load Balancers that have diagnostics logs disabled. As a best practice, enable diagnostic logs to start collecting the data available through these logs.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-LT-4', 'Azure Security Benchmark (v2)-LT-5', 'Azure Security Benchmark (v3)-DS-7', 'Azure Security Benchmark (v3)-LT-3', 'Azure Security Benchmark (v3)-LT-4', 'Azure Security Benchmark (v3)-LT-5', 'Brazilian Data Protection Law (LGPD)-Article 34', 'CIS', 'CIS v1.2.0 (Azure)-5.3', 'CIS v1.3.0 (Azure)-5.3', 'CIS v1.3.1 (Azure)-5.3', 'CIS v1.4.0 (Azure)-5.3', 'CSA CCM', 'CSA CCM v.4.0.1-LOG-05', 'CSA CCM v.4.0.1-LOG-06', 'CSA CCM v.4.0.1-LOG-08', 'CSA CCM v.4.0.1-LOG-13', "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.177', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.185', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:09.ab', 'HITRUST v.9.4.2-Control Reference:09.ac', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.4.1', 'ISO/IEC 27002:2013-12.4.3', 'ISO/IEC 27002:2013-12.4.4', 'ISO/IEC 27002:2013-16.1.1', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.4.1', 'ISO/IEC 27017:2015-12.4.4', 'ISO/IEC 27017:2015-16.1.2', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1562.008 - Impair Defenses:Disable Cloud Logs', 'NIST 800', 'NIST 800-53 Rev 5-Vulnerability Monitoring and Scanning \| Review Historic Audit Logs', 'NIST 800-53 Rev4-RA-5 (8)', 'NIST CSF', 'NIST CSF-PR.PT-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.14.2e', 'PCI DSS', 'PCI DSS v3.2.1-10.2.3', 'PCI DSS v3.2.1-10.6']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.storage/storageaccounts/providers/diagnosticsettings', 'microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings', 'microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings', 'microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings', 'microsoft.network/loadbalancers/providers/diagnosticsettings', 'microsoft.keyvault/vaults/providers/diagnosticsettings']


[diagnosticsettings.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/diagnosticsettings.rego
