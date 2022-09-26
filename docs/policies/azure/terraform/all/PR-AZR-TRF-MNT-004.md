



# Title: Azure Storage Account auditing retention should be 90 days or more


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-MNT-004

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([diagnosticsettings.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-MNT-004|
|eval|data.rule.log_storage_retention|
|message|data.rule.log_storage_retention_err|
|remediationDescription|In 'azurerm_monitor_diagnostic_setting' resource, set 'enabled = true', category = 'auditevent', 'retention_policy.enabled = true' and 'retention_policy.days = 90' under 'log' block to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting#log' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_MNT_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Storage Accounts which have Auditing Retentions less than 90 days. Audit Logs can be used to check for anomalies and gives insight into suspected breaches or misuse of information and access. It is recommended to configure Storage Account Audit Log Retention to be greater than or equal to 90 days.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_storage_queue', 'azurerm_monitor_diagnostic_setting', 'azurerm_lb', 'azurerm_storage_table', 'azurerm_storage_blob', 'azurerm_storage_account', 'azurerm_key_vault']


[diagnosticsettings.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/diagnosticsettings.rego
