



# Title: Ensure Azure SQL Database Auditing Retention is minimum 90 days or more


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-SQL-005

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbauditingsettings.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-005|
|eval|data.rule.mssql_db_log_retention|
|message|data.rule.mssql_db_log_retention_err|
|remediationDescription|In 'azurerm_mssql_database_extended_auditing_policy' resource, set the 'retention_in_days = 90' to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_database_extended_auditing_policy#retention_in_days' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies SQL Databases which have Auditing Retention less than 90 days. Audit Logs can be used to check for anomalies and gives insight into suspected breaches or misuse of information and access. It is recommended to configure SQL database Audit Retention to be greater than or equal to 90 days.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'Brazilian Data Protection Law (LGPD)-Article 16', 'Brazilian Data Protection Law (LGPD)-Article 40', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CSA CCM', 'CSA CCM v3.0.1-BCR-11', 'CSA CCM v3.0.1-GRM-01', 'CSA CCM v3.0.1-MOS-19', "CyberSecurity Law of the People's Republic of China-Article 34", "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.2.042', 'HIPAA', 'HIPAA-164.312(b)', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:06.c', 'HITRUST CSF v9.3-Control Reference:06.d', 'HITRUST CSF v9.3-Control Reference:09.aa', 'HITRUST CSF v9.3-Control Reference:09.q', 'HITRUST CSF v9.3-Control Reference:10.k', 'HITRUST CSF v9.3-Control Reference:11.e', 'ISO 27001:2013', 'ISO 27001:2013-A.12.4.2', 'ISO 27001:2013-A.18.1.3', 'NIST 800', 'NIST 800-53 Rev4-AU-11', 'NIST 800-53 Rev4-CM-2 (3)', 'NIST 800-53 Rev4-SI-12', 'NIST CSF', 'NIST CSF-PR.IP-2', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.2', 'NIST SP 800-172-3.1.1e', 'PCI DSS', 'PCI DSS v3.2.1-10.7', 'PIPEDA', 'PIPEDA-4.5.2', 'SOC 2', 'SOC 2-CC6.1', 'SOC 2-CC6.6', 'SOC 2-CC7.2', 'SOC 2-CC7.3', 'SOC 2-CC7.4', 'SOC 2-CC7.5', 'SOC 2-CC8.1']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_mssql_database', 'azurerm_mssql_database_extended_auditing_policy']


[dbauditingsettings.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/dbauditingsettings.rego
