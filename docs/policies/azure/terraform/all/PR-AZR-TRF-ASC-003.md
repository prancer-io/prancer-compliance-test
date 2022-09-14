



# Master Test ID: PR-AZR-TRF-ASC-003


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(securitycontacts.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-ASC-003|
|eval: |data.rule.securitycontacts_alert_notifications_enabled|
|message: |data.rule.securitycontacts_alert_notifications_enabled_err|
|remediationDescription: |In 'azurerm_security_center_contact' resource, set 'alert_notifications = true' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#alert_notifications' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_ASC_003.py|


severity: Medium

title: Security Center shoud send security alerts notifications to the security contact

description: This policy will identify security centers which dont have configuration enabled to send security alerts notifications to the security contact and alert if missing.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service: |['terraform']|


resourceTypes: ['azurerm_security_center_contact']


[file(securitycontacts.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/securitycontacts.rego
