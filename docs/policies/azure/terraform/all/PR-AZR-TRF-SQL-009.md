



# Title: Azure SQL Database Server security alert policies thread retention should be configured for 90 days or more


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-SQL-009

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbsecurityalertpolicies.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-009|
|eval|data.rule.sql_dbsec_threat_retention|
|message|data.rule.sql_dbsec_threat_retention_err|
|remediationDescription|In 'azurerm_mssql_server_security_alert_policy' resource, set 'retention_days = 90' to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy#retention_days' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_009.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy identifies SQL Databases which have Threat Retention configured for less than 90 days. Threat Logs can be used to check for anomalies and gives an understanding of suspected breaches or misuse of data and access. It is recommended to configure SQL database Threat Retention to be 90 days or more.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'Brazilian Data Protection Law (LGPD)-Article 16', 'Brazilian Data Protection Law (LGPD)-Article 40', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CSA CCM', 'CSA CCM v.4.0.1-LOG-05', 'CSA CCM v.4.0.1-LOG-06', 'CSA CCM v.4.0.1-LOG-08', 'CSA CCM v.4.0.1-LOG-13', "CyberSecurity Law of the People's Republic of China-Article 34", "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.2.042', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:06.c', 'HITRUST v.9.4.2-Control Reference:06.d', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.4.1', 'ISO/IEC 27002:2013-12.4.3', 'ISO/IEC 27002:2013-12.4.4', 'ISO/IEC 27002:2013-16.1.1', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.4.1', 'ISO/IEC 27017:2015-12.4.4', 'ISO/IEC 27017:2015-16.1.2', 'NIST 800', 'NIST 800-53 Rev 5-Audit Record Retention', 'NIST 800-53 Rev4-AU-11', 'NIST CSF', 'NIST CSF-DE.AE-2', 'NIST CSF-DE.CM-3', 'NIST CSF-PR.PT-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.2', 'NIST SP 800-172-3.1.1e', 'PCI DSS', 'PCI DSS v3.2.1-3.1', 'PIPEDA', 'PIPEDA-4.5.2']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_sql_server', 'azurerm_mssql_server_security_alert_policy']


[dbsecurityalertpolicies.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/dbsecurityalertpolicies.rego
