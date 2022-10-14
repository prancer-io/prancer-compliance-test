



# Title: Azure SQL Server advanced data security should have email alert recipient to get scan notification


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-053

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_399', 'AZRSNP_400']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_vulnerabilityassessments.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-053|
|eval|data.rule.sql_ads_mail|
|message|data.rule.sql_ads_mail_err|
|remediationDescription|Make sure you are following the ARM template guidelines for SQL Server by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/vulnerabilityassessments?tabs=json' target='_blank'>here</a>. Specify e-mail addresses at recurringScans.emails property to which the scan notification would be sent.|
|remediationFunction|PR_AZR_CLD_SQL_053.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification.<br><br>This policy identifies Azure SQL Servers that do not have an email address configured for ADS alert notifications. As a best practice, provide one or more email addresses where you want to receive alerts for any anomalous activities detected on SQL Servers.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Azure Security Benchmark (v2)-GS-7', 'Azure Security Benchmark (v2)-IR-1', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-IR-4', 'Azure Security Benchmark (v2)-IR-6', 'Azure Security Benchmark (v3)-DS-6', 'Azure Security Benchmark (v3)-PV-5', 'CIS', 'CIS v1.2.0 (Azure)-4.2.7', 'CIS v1.3.0 (Azure)-4.2.4', 'CIS v1.3.1 (Azure)-4.2.4', 'CIS v1.4.0 (Azure)-4.2.4', 'CSA CCM', 'CSA CCM v.4.0.1-A&A-03', 'CSA CCM v.4.0.1-AIS-01', 'CSA CCM v.4.0.1-AIS-02', 'CSA CCM v.4.0.1-AIS-04', 'CSA CCM v.4.0.1-CCC-01', 'CSA CCM v.4.0.1-GRC-03', 'CSA CCM v.4.0.1-IVS-04', 'CSA CCM v.4.0.1-TVM-01', 'CSA CCM v.4.0.1-TVM-02', 'CSA CCM v.4.0.1-TVM-04', 'CSA CCM v.4.0.1-TVM-07', 'CSA CCM v.4.0.1-TVM-08', 'CSA CCM v.4.0.1-TVM-09', 'CSA CCM v.4.0.1-TVM-10', 'CSA CCM v.4.0.1-UEM-03', 'CSA CCM v.4.0.1-UEM-06', 'CSA CCM v.4.0.1-UEM-09', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-10.1.1', 'ISO/IEC 27002:2013-12.1.2', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.6.1', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.2.1', 'ISO/IEC 27002:2013-14.2.2', 'ISO/IEC 27002:2013-14.2.4', 'ISO/IEC 27002:2013-16.1.2', 'ISO/IEC 27002:2013-16.1.3', 'ISO/IEC 27002:2013-18.2.1', 'ISO/IEC 27002:2013-5.1.1', 'ISO/IEC 27002:2013-5.1.2', 'ISO/IEC 27002:2013-6.2.1', 'ISO/IEC 27002:2013-6.2.2', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.1.2', 'ISO/IEC 27017:2015-12.2.1', 'ISO/IEC 27017:2015-14.1.1', 'ISO/IEC 27017:2015-14.1.2', 'ISO/IEC 27017:2015-14.2.1', 'ISO/IEC 27017:2015-14.2.5', 'ISO/IEC 27017:2015-5.1.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-12.1.2', 'ISO/IEC 27018:2019-18.2.1', 'NIST CSF', 'NIST CSF-DE.CM-4', 'NIST CSF-ID.RA-1', 'NIST CSF-ID.RA-2', 'NIST CSF-ID.RA-3', 'NIST CSF-PR.IP-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.9', 'NIST SP 800-171 Revision 2-3.14.3', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-A3.3.1']|
|service|['Databases']|



[sql_vulnerabilityassessments.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/sql_vulnerabilityassessments.rego
