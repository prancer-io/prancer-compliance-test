



# Master Test ID: PR-AZR-TRF-SQL-004


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbauditingsettings.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-004|
|eval|data.rule.mssql_db_log_audit|
|message|data.rule.mssql_db_log_audit_err|
|remediationDescription|In 'azurerm_mssql_database_extended_auditing_policy' resource, set the 'database_id' from associated 'azurerm_mssql_database' resource's terraform deployment output to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_database_extended_auditing_policy#database_id' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Auditing for SQL database should be enabled

***<font color="white">Description:</font>*** Database events are tracked by the Auditing feature and the events are written to an audit log in your Azure storage account. This process helps you to monitor database activity, and get insight into anomalies that could indicate business concerns or suspected security violations.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 31', 'Brazilian Data Protection Law (LGPD)-Article 48', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CSA CCM', 'CSA CCM v3.0.1-CCC-04', 'CSA CCM v3.0.1-IAM-03', 'CSA CCM v3.0.1-IAM-06', "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.3.046', 'GDPR-Article 30', 'HIPAA', 'HIPAA-164.312(b)', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:01.s', 'HITRUST CSF v9.3-Control Reference:06.i', 'HITRUST CSF v9.3-Control Reference:09.aa', 'HITRUST CSF v9.3-Control Reference:09.ab', 'HITRUST CSF v9.3-Control Reference:09.ad', 'HITRUST CSF v9.3-Control Reference:09.ae', 'HITRUST CSF v9.3-Control Reference:10.k', 'ISO 27001:2013', 'ISO 27001:2013-A.12.4.2', 'ISO 27001:2013-A.18.1.3', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1562.008 - Impair Defenses:Disable Cloud Logs', 'NIST 800', 'NIST 800-53 Rev4-AU-2a', 'NIST 800-53 Rev4-CM-5 (1)', 'NIST 800-53 Rev4-SI-7 (8)', 'NIST CSF', 'NIST CSF-PR.PT-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.14.2e', 'PCI DSS', 'PCI DSS v3.2.1-10.3', 'PIPEDA', 'PIPEDA-4.1.4', 'SOC 2', 'SOC 2-CC6.1', 'SOC 2-CC8.1']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_mssql_database', 'azurerm_mssql_database_extended_auditing_policy']


[dbauditingsettings.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/dbauditingsettings.rego
