



# Title: Ensure ssl enforcement is enabled on MySQL server Database Server.


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-016

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbforMySQL.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-016|
|eval|data.rule.ssl_enforcement|
|message|data.rule.ssl_enforcement_err|
|remediationDescription|For Resource type 'microsoft.dbformysql/servers' make sure sslEnforcement exists and the value is set to 'Enabled'.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformysql/servers' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_SQL_016.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Enable SSL connection on MySQL Servers databases. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-DP-4', 'Azure Security Benchmark (v3)-DP-3', 'CIS', 'CIS v1.1 (Azure)-4.11', 'CIS v1.2.0 (Azure)-4.3.2', 'CIS v1.3.0 (Azure)-4.3.2', 'CIS v1.3.1 (Azure)-4.3.2', 'CIS v1.4.0 (Azure)-4.4.1', 'CSA CCM', 'CSA CCM v.4.0.1-CEK-03', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-IVS-03', 'CSA CCM v.4.0.1-UEM-11', "CyberSecurity Law of the People's Republic of China-Article 21", "CyberSecurity Law of the People's Republic of China-Article 40", 'HITRUST', 'HITRUST v.9.4.2-Control Reference:09.s', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-10.1.1', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.3.1', 'ISO/IEC 27002:2013-13.1.1', 'ISO/IEC 27002:2013-13.1.2', 'ISO/IEC 27002:2013-13.1.3', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.1.3', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-8.3.1', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-10.1.1', 'ISO/IEC 27017:2015-10.1.2', 'ISO/IEC 27017:2015-6.1.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-10.1.2', 'ISO/IEC 27018:2019-12.3.1', 'NIST 800', 'NIST 800-53 Rev 5-Transmission Confidentiality and Integrity \| Cryptographic Protection', 'NIST 800-53 Rev4-SC-8 (1)', 'NIST CSF', 'NIST CSF-PR.DS-2', 'NIST CSF-PR.DS-5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.8', 'NIST SP 800-172-3.1.3e', 'PCI DSS', 'PCI DSS v3.2.1-2.3', 'PCI DSS v3.2.1-4.1']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.dbformysql/servers']


[dbforMySQL.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/dbforMySQL.rego
