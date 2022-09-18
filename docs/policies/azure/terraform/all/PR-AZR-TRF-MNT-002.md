



# Title: Azure Key Vault diagnostics logs should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-MNT-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([diagnosticsettings.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-MNT-002|
|eval|data.rule.log_keyvault|
|message|data.rule.log_keyvault_err|
|remediationDescription|Make sure resource 'azurerm_key_vault' and 'azurerm_monitor_diagnostic_setting' both exist and in 'azurerm_monitor_diagnostic_setting' resource, set 'enabled = true' and category = 'auditevent' under 'log' block to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting#log' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_MNT_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Azure Key Vault provide different types of logs alert events, health probe, metrics to help you manage and troubleshoot issues. This policy identifies Azure Key Vault that have diagnostics logs disabled. As a best practice, enable diagnostic logs to start collecting the data available through these logs.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-LT-4', 'Azure Security Benchmark (v2)-LT-5', 'Azure Security Benchmark (v3)-DS-7', 'Azure Security Benchmark (v3)-LT-3', 'Azure Security Benchmark (v3)-LT-4', 'Azure Security Benchmark (v3)-LT-5', 'CIS', 'CIS v1.2.0 (Azure)-5.3', 'CIS v1.3.0 (Azure)-5.3', 'CIS v1.3.1 (Azure)-5.3', 'CIS v1.4.0 (Azure)-5.3', 'CSA CCM', 'CSA CCM v.4.0.1-LOG-05', 'CSA CCM v.4.0.1-LOG-06', 'CSA CCM v.4.0.1-LOG-08', 'CSA CCM v.4.0.1-LOG-13', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:09.ab', 'HITRUST v.9.4.2-Control Reference:09.ac', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.4.1', 'ISO/IEC 27002:2013-12.4.3', 'ISO/IEC 27002:2013-12.4.4', 'ISO/IEC 27002:2013-16.1.1', 'ISO/IEC 27017:2015-12.4.1', 'ISO/IEC 27017:2015-12.4.4', 'ISO/IEC 27017:2015-16.1.2', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1562.008 - Impair Defenses:Disable Cloud Logs', 'NIST CSF', 'NIST CSF-PR.PT-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.14.2e', 'PCI DSS', 'PCI DSS v3.2.1-10.2.3', 'PCI DSS v3.2.1-10.6']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_key_vault', 'azurerm_monitor_diagnostic_setting']


[diagnosticsettings.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/diagnosticsettings.rego
