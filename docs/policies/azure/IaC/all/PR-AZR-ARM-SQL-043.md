



# Title: Ensure that SQL Server Auditing is Enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-043

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_servers_auditing.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-043|
|eval|data.rule.sql_logical_server_log_audit|
|message|data.rule.sql_logical_server_log_audit_err|
|remediationDescription|In Resource of type "Microsoft.Sql/servers/auditingSettings" make sure properties.state exists and value is set to "Enabled" .<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2021-02-01-preview/servers/auditingsettings' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_SQL_043.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure that SQL Server Auditing is enabled in order to keep track of Audit events.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-LT-4', 'Azure Security Benchmark (v3)-DS-7', 'Azure Security Benchmark (v3)-LT-3', 'Azure Security Benchmark (v3)-LT-4', 'Brazilian Data Protection Law (LGPD)-Article 31', 'Brazilian Data Protection Law (LGPD)-Article 48', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.1 (Azure)-4.1', 'CIS v1.2.0 (Azure)-4.1.1', 'CIS v1.3.0 (Azure)-4.1.1', 'CIS v1.3.1 (Azure)-4.1.1', 'CIS v1.4.0 (Azure)-4.1.1', 'CSA CCM', 'CSA CCM v.4.0.1-LOG-05', 'CSA CCM v.4.0.1-LOG-06', 'CSA CCM v.4.0.1-LOG-08', 'CSA CCM v.4.0.1-LOG-13', "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.3.046', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.4.1', 'ISO/IEC 27002:2013-12.4.3', 'ISO/IEC 27002:2013-12.4.4', 'ISO/IEC 27002:2013-16.1.1', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.4.1', 'ISO/IEC 27017:2015-12.4.4', 'ISO/IEC 27017:2015-16.1.2', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1562.008 - Impair Defenses:Disable Cloud Logs', 'NIST 800', 'NIST 800-53 Rev 5-Vulnerability Monitoring and Scanning \| Review Historic Audit Logs', 'NIST 800-53 Rev4-RA-5 (8)', 'NIST CSF', 'NIST CSF-PR.PT-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.14.2e', 'PCI DSS', 'PCI DSS v3.2.1-A3.3.1', 'PIPEDA', 'PIPEDA-4.1.4']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers', 'microsoft.sql/servers/auditingsettings']


[sql_servers_auditing.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers_auditing.rego
