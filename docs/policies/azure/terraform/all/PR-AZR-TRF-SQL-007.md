



# Master Test ID: PR-AZR-TRF-SQL-007


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbfirewallrules.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-007|
|eval|data.rule.mssql_firewall_not_allowing_full_inbound_access|
|message|data.rule.mssql_firewall_not_allowing_full_inbound_access_err|
|remediationDescription|In 'azurerm_mssql_firewall_rule' resource, set valid ip range other then '0.0.0.0' between 'start_ip_address' and 'end_ip_address' to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_firewall_rule' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_007.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** SQL Server Firewall rules should not configure to allow full inbound access to everyone

***<font color="white">Description:</font>*** Firewalls grant access to databases based on the originating IP address of each request and should be within the range of START IP and END IP. Firewall settings with START IP and END IP both with "0.0.0.0" represents access to all Azure internal network. This setting needs to be turned-off to remove blanket access.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA CCM', 'CSA CCM v.4.0.1-A&A-03', 'CSA CCM v.4.0.1-CEK-03', 'CSA CCM v.4.0.1-DSP-07', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-DSP-17', 'CSA CCM v.4.0.1-HRS-04', 'CSA CCM v.4.0.1-IVS-03', 'CSA CCM v.4.0.1-LOG-05', 'CSA CCM v.4.0.1-LOG-13', 'CSA CCM v.4.0.1-STA-14', 'CSA CCM v.4.0.1-TVM-01', 'CSA CCM v.4.0.1-TVM-07', 'CSA CCM v.4.0.1-TVM-08', 'CSA CCM v.4.0.1-TVM-09', 'CSA CCM v.4.0.1-TVM-10', 'CSA CCM v.4.0.1-UEM-03', 'CSA CCM v.4.0.1-UEM-05', 'CSA CCM v.4.0.1-UEM-11', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:01.n', 'HITRUST v.9.4.2-Control Reference:01.o', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-10.1.1', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.3.1', 'ISO/IEC 27002:2013-12.4.3', 'ISO/IEC 27002:2013-12.6.1', 'ISO/IEC 27002:2013-12.6.2', 'ISO/IEC 27002:2013-13.1.1', 'ISO/IEC 27002:2013-13.1.2', 'ISO/IEC 27002:2013-13.1.3', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.1.3', 'ISO/IEC 27002:2013-14.2.4', 'ISO/IEC 27002:2013-14.2.5', 'ISO/IEC 27002:2013-16.1.1', 'ISO/IEC 27002:2013-16.1.2', 'ISO/IEC 27002:2013-16.1.3', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-18.1.4', 'ISO/IEC 27002:2013-18.2.1', 'ISO/IEC 27002:2013-5.1.1', 'ISO/IEC 27002:2013-6.2.2', 'ISO/IEC 27002:2013-8.3.1', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-10.1.1', 'ISO/IEC 27017:2015-10.1.2', 'ISO/IEC 27017:2015-16.1.2', 'ISO/IEC 27017:2015-6.1.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-10.1.2', 'ISO/IEC 27018:2019-12.3.1', 'ISO/IEC 27018:2019-18.2.1', 'NIST CSF', 'NIST CSF-DE.AE-2', 'NIST CSF-DE.CM-6', 'NIST CSF-DE.CM-7', 'NIST CSF-DE.DP-2', 'NIST CSF-ID.RA-1', 'NIST CSF-PR.AC-5', 'NIST CSF-PR.DS-1', 'NIST CSF-PR.DS-5', 'NIST CSF-PR.PT-4', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.6', 'NIST SP 800-171 Revision 2-3.14.6', 'NIST SP 800-172-3.14.2e', 'PCI DSS', 'PCI DSS v3.2.1-1.2.1']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_mssql_server', 'azurerm_mssql_firewall_rule']


[dbfirewallrules.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/dbfirewallrules.rego
