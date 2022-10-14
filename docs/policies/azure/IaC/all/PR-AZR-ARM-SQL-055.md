



# Title: Azure SQL Server advanced data security should send alerts to subscription administrators


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-055

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_vulnerabilityassessments.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-055|
|eval|data.rule.db_ads_alert|
|message|data.rule.db_ads_alert_err|
|remediationDescription|Make sure you are following the ARM template guidelines for SQL Server by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/vulnerabilityassessments?tabs=json' target='_blank'>here</a>. Specify admin e-mail address at recurringScans.emailSubscriptionAdmins property where the schedule scan notification would be sent.|
|remediationFunction|PR_AZR_ARM_SQL_055.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification.<br><br>This policy identifies Azure SQL Servers that are not enabled with ADS. As a best practice, enable ADS so that the subscription admin can receive email alerts when anomalous activities are detected on the SQL Servers.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Azure Security Benchmark', 'Azure Security Benchmark (v2)-PV-6', 'Azure Security Benchmark (v3)-DS-6', 'Azure Security Benchmark (v3)-PV-5', 'CIS', 'CIS v1.2.0 (Azure)-4.2.8', 'CIS v1.3.0 (Azure)-4.2.5', 'CIS v1.3.1 (Azure)-4.2.5', 'CIS v1.4.0 (Azure)-4.2.5', 'CSA CCM', 'CSA CCM v.4.0.1-A&A-03', 'CSA CCM v.4.0.1-AIS-01', 'CSA CCM v.4.0.1-AIS-02', 'CSA CCM v.4.0.1-AIS-04', 'CSA CCM v.4.0.1-CCC-01', 'CSA CCM v.4.0.1-GRC-03', 'CSA CCM v.4.0.1-IVS-04', 'CSA CCM v.4.0.1-TVM-01', 'CSA CCM v.4.0.1-TVM-02', 'CSA CCM v.4.0.1-TVM-04', 'CSA CCM v.4.0.1-TVM-07', 'CSA CCM v.4.0.1-TVM-08', 'CSA CCM v.4.0.1-TVM-09', 'CSA CCM v.4.0.1-TVM-10', 'CSA CCM v.4.0.1-UEM-03', 'CSA CCM v.4.0.1-UEM-06', 'CSA CCM v.4.0.1-UEM-09', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-10.1.1', 'ISO/IEC 27002:2013-12.1.2', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.6.1', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.2.1', 'ISO/IEC 27002:2013-14.2.2', 'ISO/IEC 27002:2013-14.2.4', 'ISO/IEC 27002:2013-16.1.2', 'ISO/IEC 27002:2013-16.1.3', 'ISO/IEC 27002:2013-18.2.1', 'ISO/IEC 27002:2013-5.1.1', 'ISO/IEC 27002:2013-5.1.2', 'ISO/IEC 27002:2013-6.2.1', 'ISO/IEC 27002:2013-6.2.2', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.1.2', 'ISO/IEC 27017:2015-12.2.1', 'ISO/IEC 27017:2015-14.1.1', 'ISO/IEC 27017:2015-14.1.2', 'ISO/IEC 27017:2015-14.2.1', 'ISO/IEC 27017:2015-14.2.5', 'ISO/IEC 27017:2015-5.1.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-12.1.2', 'ISO/IEC 27018:2019-18.2.1', 'NIST CSF', 'NIST CSF-DE.CM-4', 'NIST CSF-ID.RA-1', 'NIST CSF-ID.RA-2', 'NIST CSF-ID.RA-3', 'NIST CSF-PR.IP-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.9', 'NIST SP 800-171 Revision 2-3.14.3', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-A3.3.1']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers', 'microsoft.sql/servers/vulnerabilityassessments']


[sql_vulnerabilityassessments.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_vulnerabilityassessments.rego
