



# Master Test ID: PR-AZR-TRF-MNT-001


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(activitylogalerts.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-MNT-001|
|eval: |data.rule.azure_monitor_activity_log_alert_enabled|
|message: |data.rule.azure_monitor_activity_log_alert_enabled_err|
|remediationDescription: |In 'azurerm_monitor_activity_log_alert' resource, set 'enabled = true' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert#enabled' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_MNT_001.py|


severity: Low

title: Activity log alerts should be enabled

description: Activity log alerts are alerts that activate when a new activity log event occurs that matches the conditions specified in the alert. Based on the order and volume of the events recorded in Azure activity log, the alert rule will fire. Enabling Activity log alerts will allow Azure to send you emails about any high severity alerts in your environment. This will make sure that you are aware of any security issues and take prompt actions to mitigate the risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service: |['terraform']|


resourceTypes: ['azurerm_monitor_activity_log_alert', 'azurerm_monitor_log_profile']


[file(activitylogalerts.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/activitylogalerts.rego
