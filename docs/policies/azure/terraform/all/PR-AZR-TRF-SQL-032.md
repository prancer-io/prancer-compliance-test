



# Title: Ensure SQL server's TDE protector is encrypted with Customer-managed key


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-SQL-032

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_servers_encryption.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-032|
|eval|data.rule.sql_serverKeyType|
|message|data.rule.sql_serverKeyType_err|
|remediationDescription|Make sure resource 'azurerm_sql_server' and 'azurerm_mssql_server_transparent_data_encryption' both exist and in 'azurerm_mssql_server_transparent_data_encryption' resource, make sure 'key_vault_key_id' property has id of associated 'azurerm_key_vault_key' resource to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_transparent_data_encryption#key_vault_key_id' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_032.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Customer-managed key support for Transparent Data Encryption (TDE) allows user control of TDE encryption keys and restricts who can access them and when. Azure Key Vault, Azure cloud-based external key management system is the first key management service where TDE has integrated support for Customer-managed keys. With Customer-managed key support, the database encryption key is protected by an asymmetric key stored in the Key Vault. The asymmetric key is set at the server level and inherited by all databases under that server.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-DP-5', 'Azure Security Benchmark (v3)-DP-4', 'Azure Security Benchmark (v3)-DP-5', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CIS', 'CIS v1.1 (Azure)-4.10', 'CIS v1.2.0 (Azure)-4.5', 'CIS v1.3.0 (Azure)-4.5', 'CIS v1.3.1 (Azure)-4.5', 'CIS v1.4.0 (Azure)-4.6', 'CSA CCM', 'CSA CCM v.4.0.1-CEK-03', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-UEM-11', "CyberSecurity Law of the People's Republic of China-Article 30", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 40", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.177', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:06.d', 'HITRUST v.9.4.2-Control Reference:09.s', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-10.1.1', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.3.1', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.1.3', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-8.3.1', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-10.1.1', 'ISO/IEC 27017:2015-10.1.2', 'ISO/IEC 27017:2015-6.1.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-10.1.2', 'ISO/IEC 27018:2019-12.3.1', 'NIST 800', 'NIST 800-53 Rev 5-Cryptographic Key Establishment and Management', 'NIST 800-53 Rev 5-Remote Access \| Protection of Confidentiality and Integrity Using Encryption', 'NIST 800-53 Rev 5-Transmission Confidentiality and Integrity \| Cryptographic Protection', 'NIST 800-53 Rev4-AC-17 (2)', 'NIST 800-53 Rev4-SC-12', 'NIST 800-53 Rev4-SC-8 (1)', 'NIST CSF', 'NIST CSF-PR.DS-1', 'NIST CSF-PR.DS-5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.16', 'NIST SP 800-172-3.1.3e', 'PCI DSS', 'PCI DSS v3.2.1-3.4.1', 'PCI DSS v3.2.1-4.1']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_sql_server', 'azurerm_mssql_server_transparent_data_encryption']


[sql_servers_encryption.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers_encryption.rego
