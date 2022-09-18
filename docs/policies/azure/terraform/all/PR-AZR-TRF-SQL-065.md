



# Title: PostgreSQL Database Server should have connection_throttling enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-SQL-065

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([postgreSQL.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-065|
|eval|data.rule.azurerm_postgresql_configuration_connection_throttling|
|message|data.rule.azurerm_postgresql_configuration_connection_throttling_err|
|remediationDescription|In 'azurerm_postgresql_configuration' resource, set name = 'connection_throttling' and value = 'on' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_configuration' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_065.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Enabling connection_throttling allows the PostgreSQL Database to set the verbosity of logged messages which in turn generates query and error logs with respect to concurrent connections, that could lead to a successful Denial of Service (DoS) attack by exhausting connection resources.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-LT-4', 'Azure Security Benchmark (v3)-DS-7', 'Brazilian Data Protection Law (LGPD)-Article 31', 'Brazilian Data Protection Law (LGPD)-Article 48', 'CIS', 'CIS v1.1 (Azure)-4.17', 'CIS v1.2.0 (Azure)-4.3.7', 'CIS v1.3.0 (Azure)-4.3.6', 'CIS v1.3.1 (Azure)-4.3.6', 'CIS v1.4.0 (Azure)-4.3.5', 'CSA CCM', 'CSA CCM v.4.0.1-LOG-05', 'CSA CCM v.4.0.1-LOG-06', 'CSA CCM v.4.0.1-LOG-08', 'CSA CCM v.4.0.1-LOG-13', 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.3.046', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:09.ab', 'HITRUST v.9.4.2-Control Reference:09.ac', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.4.1', 'ISO/IEC 27002:2013-12.4.3', 'ISO/IEC 27002:2013-12.4.4', 'ISO/IEC 27002:2013-16.1.1', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.4.1', 'ISO/IEC 27017:2015-12.4.4', 'ISO/IEC 27017:2015-16.1.2', 'NIST 800', 'NIST 800-53 Rev 5-Configuration Settings', 'NIST 800-53 Rev4-CM-6', 'NIST CSF', 'NIST CSF-PR.PT-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-10.2.3', 'PCI DSS v3.2.1-10.6']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_postgresql_configuration', 'azurerm_postgresql_server', 'azurerm_postgresql_firewall_rule']


[postgreSQL.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego
