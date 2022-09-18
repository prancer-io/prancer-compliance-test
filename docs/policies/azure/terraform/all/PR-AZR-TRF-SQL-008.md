



# Title: SQL Database Server should have security alert policies enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-SQL-008

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbsecurityalertpolicies.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-008|
|eval|data.rule.sql_dbsec_threat_off|
|message|data.rule.sql_dbsec_threat_off_err|
|remediationDescription|In 'azurerm_mssql_server_security_alert_policy' resource, set state = 'Enabled' to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy#state' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_008.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** SQL Threat Detection provides a new layer of security, which enables customers to detect and respond to potential threats as they occur by providing security alerts on anomalous activities. Users will receive an alert upon suspicious database activities, potential vulnerabilities, and SQL injection attacks, as well as anomalous database access patterns. SQL Threat Detection alerts provide details of suspicious activity and recommend action on how to investigate and mitigate the threat.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-DP-3', 'Azure Security Benchmark (v3)-DS-6', 'Azure Security Benchmark (v3)-PV-5', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.1 (Azure)-4.4', 'CIS v1.2.0 (Azure)-4.2.1', 'CIS v1.3.0 (Azure)-4.2.1', 'CIS v1.3.1 (Azure)-4.2.1', 'CIS v1.4.0 (Azure)-4.2.1', 'CSA CCM', 'CSA CCM v.4.0.1-AIS-01', 'CSA CCM v.4.0.1-AIS-02', 'CSA CCM v.4.0.1-AIS-04', 'CSA CCM v.4.0.1-CCC-01', 'CSA CCM v.4.0.1-GRC-03', 'CSA CCM v.4.0.1-IVS-04', 'CSA CCM v.4.0.1-UEM-06', "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AM.4.226', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:10.a', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.1.2', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.2.1', 'ISO/IEC 27002:2013-14.2.2', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.1.2', 'ISO/IEC 27017:2015-14.1.1', 'ISO/IEC 27017:2015-14.1.2', 'ISO/IEC 27017:2015-14.2.1', 'ISO/IEC 27017:2015-14.2.5', 'ISO/IEC 27017:2015-5.1.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-12.1.2', 'NIST 800', 'NIST 800-53 Rev 5-Developer Testing and Evaluation \| Threat Modeling and Vulnerability Analyses', 'NIST 800-53 Rev4-SA-11 (2)', 'NIST CSF', 'NIST CSF-PR.IP-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.4.2', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-6.3', 'PIPEDA', 'PIPEDA-4.7.3']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_sql_server', 'azurerm_mssql_server_security_alert_policy']


[dbsecurityalertpolicies.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/dbsecurityalertpolicies.rego
