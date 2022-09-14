



# Master Test ID: PR-AZR-TRF-MNT-006


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(diagnosticsettings.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-MNT-006|
|eval: |data.rule.log_queue|
|message: |data.rule.log_queue_err|
|remediationDescription: |In 'azurerm_monitor_diagnostic_setting' resource, set 'enabled = true' and category = 'auditevent' under 'log' block to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting#log' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_MNT_006.py|


severity: Medium

title: Azure storage account queue services diagnostic logs should be enabled

description: Queue logging cannot be enabled for Storage Accounts with 'kind' of BlobStorage **<br><br>Storage Logging records details of requests (read, write, and delete operations) against your Azure queues. The logs include additional information such as:<br>- Timing and server latency.<br>- Success or failure, and HTTP status code.<br>- Authentication details<br><br>This policy identifies Azure storage accounts that do not have logging enabled for queues. As a best practice, enable logging for read, write, and delete request types on queues.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service: |['terraform']|


resourceTypes: ['azurerm_storage_queue', 'azurerm_monitor_diagnostic_setting', 'azurerm_lb', 'azurerm_storage_table', 'azurerm_storage_blob', 'azurerm_storage_account', 'azurerm_key_vault']


[file(diagnosticsettings.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/diagnosticsettings.rego
