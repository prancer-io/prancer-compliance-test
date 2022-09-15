



# Master Test ID: PR-AZR-TRF-SQL-045


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbserverauditingsettings.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-045|
|eval|data.rule.sql_log_retention|
|message|data.rule.sql_log_retention_err|
|remediationDescription|In 'azurerm_sql_server' resource, set the 'retention_in_days = 90' under 'extended_auditing_policy' block to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server#retention_in_days' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_045.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Azure SQL Server audit log retention should be 90 days or more

***<font color="white">Description:</font>*** Audit Logs can help you find suspicious events, unusual activity, and trends. Auditing the SQL server, at the server-level, allows you to track all existing and newly created databases on the instance.<br><br>This policy identifies SQL servers which do not retain audit logs for 90 days or more. As a best practice, configure the audit logs retention time period to be equal or greater than 90 days.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'Azure Security Benchmark ', 'Azure Security Benchmark (v2)-LT-6', 'Azure Security Benchmark (v3)-LT-6', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.1 (Azure)-4.3', 'CIS v1.2.0 (Azure)-4.1.3', 'CIS v1.3.0 (Azure)-4.1.3', 'CIS v1.3.1 (Azure)-4.1.3', 'CIS v1.4.0 (Azure)-4.1.3', 'CSA CCM', 'CSA CCM v.4.0.1-LOG-05', 'CSA CCM v.4.0.1-LOG-06', 'CSA CCM v.4.0.1-LOG-08', 'CSA CCM v.4.0.1-LOG-13', "CyberSecurity Law of the People's Republic of China-Article 34", "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.177', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.185', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:06.c', 'HITRUST v.9.4.2-Control Reference:06.d', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.4.1', 'ISO/IEC 27002:2013-12.4.3', 'ISO/IEC 27002:2013-12.4.4', 'ISO/IEC 27002:2013-16.1.1', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.4.1', 'ISO/IEC 27017:2015-12.4.4', 'ISO/IEC 27017:2015-16.1.2', 'NIST 800', 'NIST 800-53 Rev 5-Audit Record Retention', 'NIST 800-53 Rev4-AU-11', 'NIST CSF', 'NIST CSF-DE.AE-2', 'NIST CSF-DE.CM-3', 'NIST CSF-PR.PT-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.2', 'NIST SP 800-172-3.1.1e', 'PCI DSS', 'PCI DSS v3.2.1-3.1', 'PIPEDA', 'PIPEDA-4.5.2']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_mssql_server_extended_auditing_policy', 'azurerm_mssql_server', 'azurerm_sql_server']


[dbserverauditingsettings.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/dbserverauditingsettings.rego
