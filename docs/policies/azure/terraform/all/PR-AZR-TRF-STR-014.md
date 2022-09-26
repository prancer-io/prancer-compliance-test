



# Title: Storage Accounts queue service logging should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-STR-014

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-STR-014|
|eval|data.rule.storage_account_queue_logging_enabled_for_all_operation|
|message|data.rule.storage_account_queue_logging_enabled_for_all_operation_err|
|remediationDescription|In 'azurerm_storage_account' resource, set 'read = true', 'write = true', 'delete = true' under 'logging' block which exist under 'queue_properties' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#logging' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_STR_014.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The Azure Storage Queue service logging records details for both successful and failed requests made to the queues, as well as end-to-end latency, server latency, and authentication information.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'Azure Security Benchmark (v2)-LT-4', 'Azure Security Benchmark (v3)-DS-7', 'Azure Security Benchmark (v3)-LT-3', 'Azure Security Benchmark (v3)-LT-4', 'Brazilian Data Protection Law (LGPD)-Article 31', 'Brazilian Data Protection Law (LGPD)-Article 48', 'CCPA 2018-1798.150(a)(1)', 'CIS v1.1 (Azure)-3.3', 'CIS v1.2.0 (Azure)-3.3', 'CIS v1.3.0 (Azure)-3.3', 'CIS v1.3.1 (Azure)-3.3', 'CIS v1.4.0 (Azure)-3.3', 'CSA CCM v.4.0.1-LOG-05', 'CSA CCM v.4.0.1-LOG-06', 'CSA CCM v.4.0.1-LOG-08', 'CSA CCM v.4.0.1-LOG-13', "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.3.046', 'HITRUST v.9.4.2-Control Reference:09.ab', 'HITRUST v.9.4.2-Control Reference:09.ac', 'ISO/IEC 27002:2013-12.4.1', 'ISO/IEC 27002:2013-12.4.3', 'ISO/IEC 27002:2013-12.4.4', 'ISO/IEC 27002:2013-16.1.1', 'ISO/IEC 27017:2015-12.4.1', 'ISO/IEC 27017:2015-12.4.4', 'ISO/IEC 27017:2015-16.1.2', 'MITRE ATT&CK v10.0-T1562.008 - Impair Defenses:Disable Cloud Logs', 'MITRE ATT&CK v6.3-T1530', 'MITRE ATT&CK v8.2-T1530', 'NIST 800-53 Rev 5-Vulnerability Monitoring and Scanning \| Review Historic Audit Logs', 'NIST 800-53 Rev4-RA-5 (8)', 'NIST CSF-PR.PT-1', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.14.2e', 'PCI DSS v3.2.1-10.2.3', 'PCI DSS v3.2.1-10.6', 'PIPEDA-4.1.4']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_storage_account']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego
