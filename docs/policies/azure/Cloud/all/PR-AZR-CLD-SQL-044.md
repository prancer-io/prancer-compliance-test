



# Title: Azure SQL server audit log retention should be 90 days or higher


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-044

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_400']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_servers_auditing.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-044|
|eval|data.rule.sql_server_audit_log_retention|
|message|data.rule.sql_server_audit_log_retention_err|
|remediationDescription|az sql server audit-policy update -g -n --state Enabled --storage-account --retention-days 90<br><br>References:<br><a href='https://docs.microsoft.com/en-us/cli/azure/sql/server/audit-policy?view=azure-cli-latest#az_sql_server_audit_policy_show' target='_blank'>https://docs.microsoft.com/en-us/cli/azure/sql/server/audit-policy?view=azure-cli-latest#az_sql_server_audit_policy_show</a>|
|remediationFunction|PR_AZR_CLD_SQL_044.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access. We recommend you configure SQL server audit retention to be 90 days or higher.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'Azure Security Benchmark ', 'Azure Security Benchmark (v2)-LT-6', 'Azure Security Benchmark (v3)-LT-6', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.1 (Azure)-4.3', 'CIS v1.2.0 (Azure)-4.1.3', 'CIS v1.3.0 (Azure)-4.1.3', 'CIS v1.3.1 (Azure)-4.1.3', 'CIS v1.4.0 (Azure)-4.1.3', 'CSA CCM', 'CSA CCM v.4.0.1-LOG-05', 'CSA CCM v.4.0.1-LOG-06', 'CSA CCM v.4.0.1-LOG-08', 'CSA CCM v.4.0.1-LOG-13', "CyberSecurity Law of the People's Republic of China-Article 34", "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.177', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.185', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:06.c', 'HITRUST v.9.4.2-Control Reference:06.d', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.4.1', 'ISO/IEC 27002:2013-12.4.3', 'ISO/IEC 27002:2013-12.4.4', 'ISO/IEC 27002:2013-16.1.1', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.4.1', 'ISO/IEC 27017:2015-12.4.4', 'ISO/IEC 27017:2015-16.1.2', 'NIST 800', 'NIST 800-53 Rev 5-Audit Record Retention', 'NIST 800-53 Rev4-AU-11', 'NIST CSF', 'NIST CSF-DE.AE-2', 'NIST CSF-DE.CM-3', 'NIST CSF-PR.PT-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.2', 'NIST SP 800-172-3.1.1e', 'PCI DSS', 'PCI DSS v3.2.1-3.1', 'PIPEDA', 'PIPEDA-4.5.2']|
|service|['Databases']|



[sql_servers_auditing.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/sql_servers_auditing.rego
