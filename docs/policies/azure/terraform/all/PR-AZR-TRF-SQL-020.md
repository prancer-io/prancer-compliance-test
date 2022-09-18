



# Title: Azure SQL Server threat detection alerts should be enabled for all threat types


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-SQL-020

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbsecurityalertpolicies.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-020|
|eval|data.rule.dbsec_threat_alert|
|message|data.rule.dbsec_threat_alert_err|
|remediationDescription|In 'azurerm_mssql_server_security_alert_policy' resource, remove 'disabled_alerts' property or remove all the alerts element out of it to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy#disabled_alerts' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_020.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification.<br><br>This policy identifies Azure SQL servers that have disabled the detection of one or more threat types. To protect your SQL Servers, as a best practice, enable ADS detection for all types of threats.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'Brazilian Data Protection Law (LGPD)-Article 31', 'Brazilian Data Protection Law (LGPD)-Article 48', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.1 (Azure)-4.5', 'CIS v1.2.0 (Azure)-4.2.2', 'CSA CCM', 'CSA CCM v.4.0.1-LOG-05', 'CSA CCM v.4.0.1-LOG-06', 'CSA CCM v.4.0.1-LOG-08', 'CSA CCM v.4.0.1-LOG-13', "CyberSecurity Law of the People's Republic of China-Article 55", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.3.046', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.4.1', 'ISO/IEC 27002:2013-12.4.3', 'ISO/IEC 27002:2013-12.4.4', 'ISO/IEC 27002:2013-16.1.1', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.4.1', 'ISO/IEC 27017:2015-12.4.4', 'ISO/IEC 27017:2015-16.1.2', 'NIST 800', 'NIST 800-53 Rev 5-System Monitoring \| Automated Organization-generated Alerts', 'NIST 800-53 Rev4-SI-4 (12)', 'NIST CSF', 'NIST CSF-PR.PT-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.11.3e', 'PCI DSS', 'PCI DSS v3.2.1-A3.3.1', 'PIPEDA', 'PIPEDA-4.7.3']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_mssql_server', 'azurerm_mssql_server_security_alert_policy']


[dbsecurityalertpolicies.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/dbsecurityalertpolicies.rego
