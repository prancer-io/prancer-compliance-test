



# Title: Storage Accounts access should be allowed for trusted Microsoft services


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-STR-011

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-STR-011|
|eval|data.rule.storage_nr_allow_trusted_azure_services|
|message|data.rule.storage_nr_allow_trusted_azure_services_err|
|remediationDescription|In 'azurerm_storage_account_network_rules' resource or azurerm_storage_account's inner block 'network_rules', make sure array property 'bypass' exist add 'AzureServices' value under 'bypass' array property to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules#bypass' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_STR_011.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure that 'Allow trusted Microsoft services to access this storage account' exception is enabled within your Azure Storage account configuration settings to grant access to trusted cloud services.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-GS-2', 'Azure Security Benchmark (v2)-NS-1', 'Azure Security Benchmark (v3)-GS-9', 'Azure Security Benchmark (v3)-NS-1', 'Azure Security Benchmark (v3)-NS-2', 'Azure Security Benchmark (v3)-NS-3', 'Azure Security Benchmark (v3)-NS-7', 'Azure Security Benchmark (v3)-NS-8', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.1 (Azure)-3.8', 'CIS v1.2.0 (Azure)-3.7', 'CIS v1.3.0 (Azure)-3.7', 'CIS v1.3.1 (Azure)-3.7', 'CIS v1.4.0 (Azure)-3.7', 'CSA CCM', 'CSA CCM v.4.0.1-AIS-01', 'CSA CCM v.4.0.1-AIS-02', 'CSA CCM v.4.0.1-AIS-04', 'CSA CCM v.4.0.1-CCC-01', 'CSA CCM v.4.0.1-GRC-03', 'CSA CCM v.4.0.1-IVS-04', 'CSA CCM v.4.0.1-UEM-06', "CyberSecurity Law of the People's Republic of China-Article 21", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.1.001', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.1.002', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:10.a', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.1.2', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.2.1', 'ISO/IEC 27002:2013-14.2.2', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.1.2', 'ISO/IEC 27017:2015-14.1.1', 'ISO/IEC 27017:2015-14.1.2', 'ISO/IEC 27017:2015-14.2.1', 'ISO/IEC 27017:2015-14.2.5', 'ISO/IEC 27017:2015-5.1.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-12.1.2', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1199 - Trusted Relationship', 'MITRE ATT&CK v6.3-T1199', 'MITRE ATT&CK v6.3-T1530', 'MITRE ATT&CK v8.2-T1199', 'MITRE ATT&CK v8.2-T1530', 'NIST CSF', 'NIST CSF-PR.IP-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.4.2', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-6.3', 'PIPEDA', 'PIPEDA-4.7.3']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_storage_account_network_rules', 'azurerm_storage_account']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego
