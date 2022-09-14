



# Master Test ID: PR-AZR-TRF-ASC-005


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(securitycontacts.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-ASC-005|
|eval: |data.rule.securitycontacts_alerts_to_admins_enabled|
|message: |data.rule.securitycontacts_alerts_to_admins_enabled_err|
|remediationDescription: |In 'azurerm_security_center_contact' resource, set 'alerts_to_admins = true' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#alerts_to_admins' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_ASC_005.py|


severity: Medium

title: Security Center shoud send security alerts notifications to subscription admins

description: This policy will identify security centers which dont have configuration enabled to send security alerts notifications to subscription admins and alert if missing.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service: |['terraform']|


resourceTypes: ['azurerm_security_center_contact']


[file(securitycontacts.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/securitycontacts.rego
