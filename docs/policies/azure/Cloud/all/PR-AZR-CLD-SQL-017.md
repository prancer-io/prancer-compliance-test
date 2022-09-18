



# Title: SQL Databases should have security alert policies enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-017

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_263']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbsecurityalertpolicies.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-017|
|eval|data.rule.dbsec_threat_off|
|message|data.rule.dbsec_threat_off_err|
|remediationDescription|If Azure Defender is enabled at server level it will also be applied to all the database, regardless of the database Azure Defender settings. It is recommended that you enable only server-level Azure Defender settings. To enable auditing at server level: Log in to the Azure Portal. Note down the reported SQL database and SQL server. Select 'SQL servers', Click on the SQL server instance you wanted to modify. Click on 'Security Center' under 'Security'. Click on 'Enable Azure Defender for SQL'. It is recommended to avoid enabling Azure Defender in both server and database. If you want to enable different storage account, email addresses for scan and alert notifications or 'Advanced Threat Protection types' for a specific database that differ from the rest of the databases on the server. Then to enable auditing at database level by: Log in to the Azure Portal. Note down the reported SQL database. Select 'SQL databases', Click on the SQL database instance you wanted to modify. Click on 'Security Center' under 'Security'. Click on 'Enable Azure Defender for SQL'|
|remediationFunction|PR_AZR_CLD_SQL_017.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** SQL Threat Detection provides a new layer of security, which enables customers to detect and respond to potential threats as they occur by providing security alerts on anomalous activities. Users will receive an alert upon suspicious database activities, potential vulnerabilities, and SQL injection attacks, as well as anomalous database access patterns. SQL Threat Detection alerts provide details of suspicious activity and recommend action on how to investigate and mitigate the threat.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'Brazilian Data Protection Law (LGPD)-Article 31', 'Brazilian Data Protection Law (LGPD)-Article 48', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CSA CCM', 'CSA CCM v.4.0.1-A&A-03', 'CSA CCM v.4.0.1-AIS-01', 'CSA CCM v.4.0.1-AIS-02', 'CSA CCM v.4.0.1-AIS-04', 'CSA CCM v.4.0.1-CCC-01', 'CSA CCM v.4.0.1-DSP-01', 'CSA CCM v.4.0.1-DSP-04', 'CSA CCM v.4.0.1-GRC-03', 'CSA CCM v.4.0.1-IVS-04', 'CSA CCM v.4.0.1-TVM-01', 'CSA CCM v.4.0.1-TVM-07', 'CSA CCM v.4.0.1-TVM-08', 'CSA CCM v.4.0.1-TVM-09', 'CSA CCM v.4.0.1-TVM-10', 'CSA CCM v.4.0.1-UEM-03', 'CSA CCM v.4.0.1-UEM-06', "CyberSecurity Law of the People's Republic of China-Article 55", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-RM.4.150', 'ISO 27001:2013', 'ISO 27001:2013-A.14.1.2', 'ISO 27001:2013-A.16.1.4', 'ISO 27001:2013-A.18.1.3', 'ISO 27001:2013-A.8.2.3', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.1.1', 'ISO/IEC 27002:2013-12.1.2', 'ISO/IEC 27002:2013-12.6.1', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.2.1', 'ISO/IEC 27002:2013-14.2.2', 'ISO/IEC 27002:2013-14.2.4', 'ISO/IEC 27002:2013-16.1.2', 'ISO/IEC 27002:2013-16.1.3', 'ISO/IEC 27002:2013-18.2.1', 'ISO/IEC 27002:2013-5.1.1', 'ISO/IEC 27002:2013-5.1.2', 'ISO/IEC 27002:2013-8.2.1', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.1.2', 'ISO/IEC 27017:2015-14.1.1', 'ISO/IEC 27017:2015-14.1.2', 'ISO/IEC 27017:2015-14.2.1', 'ISO/IEC 27017:2015-14.2.5', 'ISO/IEC 27017:2015-5.1.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-12.1.2', 'ISO/IEC 27018:2019-18.2.1', 'NIST 800', 'NIST 800-53 Rev4-SA-11 (2)', 'NIST 800-53 Rev4-SA-15 (4)', 'NIST CSF', 'NIST CSF-DE.AE-4', 'NIST CSF-DE.CM-8', 'NIST CSF-ID.RA-1', 'NIST CSF-ID.RA-3', 'NIST CSF-ID.RA-4', 'NIST CSF-ID.RA-5', 'NIST CSF-PR.IP-1', 'NIST CSF-RS.AN-2', 'NIST CSF-RS.MI-3', 'NIST SP', 'NIST SP 800-171 Revision 2-3.11.1', 'NIST SP 800-171 Revision 2-3.11.2', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-2.2', 'PIPEDA', 'PIPEDA-4.7.3']|
|service|['Databases']|



[dbsecurityalertpolicies.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/dbsecurityalertpolicies.rego
