



# Title: Ensure SQL Server Threat Detection is Enabled and Retention Logs are equal or greater than 90 days


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-037

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_alert_policy.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-037|
|eval|data.rule.sql_logical_server_retention_days|
|message|data.rule.sql_logical_server_retention_days_err|
|remediationDescription|For Resource type 'microsoft.sql/servers/securityalertpolicies' make sure properties.retentionDays exists and the value is set to equal or greater than 90.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_SQL_037.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure SQL Database Threat Detection is a security intelligence feature built into the Azure SQL Database service. Working around the clock to learn, profile and detect anomalous database activities, Azure SQL Database Threat Detection identifies potential threats to the database. Security officers or other designated administrators can get an immediate notification about suspicious database activities as they occur. Each notification provides details of the suspicious activity and recommends how to further investigate and mitigate the threat.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'Brazilian Data Protection Law (LGPD)-Article 16', 'Brazilian Data Protection Law (LGPD)-Article 40', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CSA CCM', 'CSA CCM v3.0.1-BCR-11', 'CSA CCM v3.0.1-GRM-01', 'CSA CCM v3.0.1-MOS-19', "CyberSecurity Law of the People's Republic of China-Article 34", "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.2.042', 'HIPAA', 'HIPAA-164.312(b)', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:06.c', 'HITRUST CSF v9.3-Control Reference:06.d', 'HITRUST CSF v9.3-Control Reference:09.aa', 'HITRUST CSF v9.3-Control Reference:09.q', 'HITRUST CSF v9.3-Control Reference:10.k', 'HITRUST CSF v9.3-Control Reference:11.e', 'ISO 27001:2013', 'ISO 27001:2013-A.12.4.2', 'ISO 27001:2013-A.18.1.3', 'NIST 800', 'NIST 800-53 Rev4-AU-11', 'NIST 800-53 Rev4-CM-2 (3)', 'NIST 800-53 Rev4-SI-12', 'NIST CSF', 'NIST CSF-PR.IP-2', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.2', 'NIST SP 800-172-3.1.1e', 'PCI DSS', 'PCI DSS v3.2.1-10.7', 'PIPEDA', 'PIPEDA-4.5.2', 'SOC 2', 'SOC 2-CC6.1', 'SOC 2-CC6.6', 'SOC 2-CC7.2', 'SOC 2-CC7.3', 'SOC 2-CC7.4', 'SOC 2-CC7.5', 'SOC 2-CC8.1']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers', 'microsoft.sql/managedinstances/securityalertpolicies', 'microsoft.sql/servers/securityalertpolicies']


[sql_alert_policy.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego
