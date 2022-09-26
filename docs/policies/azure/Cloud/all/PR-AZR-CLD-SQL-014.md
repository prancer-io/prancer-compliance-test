



# Title: MySQL Database Server should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-014

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_411']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbforMySQL_firewallrules.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-014|
|eval|data.rule.mysql_ingress_from_any_ip_disabled|
|message|data.rule.mysql_ingress_from_any_ip_disabled_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/mysql/concepts-firewall-rules' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_SQL_014.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy will identify MySQL Database Server firewall rule that is currently allowing ingress from all Azure-internal IP addresses  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-DP-4', 'Azure Security Benchmark (v3)-DP-3', 'CIS', 'CIS v1.1 (Azure)-4.11', 'CIS v1.2.0 (Azure)-4.3.2', 'CIS v1.3.0 (Azure)-4.3.2', 'CIS v1.3.1 (Azure)-4.3.2', 'CIS v1.4.0 (Azure)-4.4.1', 'CSA CCM', 'CSA CCM v.4.0.1-CEK-03', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-IVS-03', 'CSA CCM v.4.0.1-UEM-11', "CyberSecurity Law of the People's Republic of China-Article 21", "CyberSecurity Law of the People's Republic of China-Article 40", 'HITRUST', 'HITRUST v.9.4.2-Control Reference:09.s, ISO/IEC 27002:2013-10.1.1', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.3.1', 'ISO/IEC 27002:2013-13.1.1', 'ISO/IEC 27002:2013-13.1.2', 'ISO/IEC 27002:2013-13.1.3', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.1.3', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-8.3.1', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-10.1.1', 'ISO/IEC 27017:2015-10.1.2', 'ISO/IEC 27017:2015-6.1.1', 'ISO/IEC 27018:2019-10.1.2', 'ISO/IEC 27018:2019-12.3.1', 'NIST 800', 'NIST 800-53 Rev 5-Transmission Confidentiality and Integrity \| Cryptographic Protection', 'NIST 800-53 Rev4-SC-8 (1)', 'NIST CSF', 'NIST CSF-PR.DS-2', 'NIST CSF-PR.DS-5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.8', 'NIST SP 800-172-3.1.3e', 'PCI DSS', 'PCI DSS v3.2.1-2.3', 'PCI DSS v3.2.1-4.1']|
|service|['Databases']|



[dbforMySQL_firewallrules.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/dbforMySQL_firewallrules.rego
