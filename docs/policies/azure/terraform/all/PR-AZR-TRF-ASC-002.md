



# Master Test ID: PR-AZR-TRF-ASC-002


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(securitycontacts.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-ASC-002|
|eval: |data.rule.securitycontacts|
|message: |data.rule.securitycontacts_err|
|remediationDescription: |In 'azurerm_security_center_contact' resource, set a valid email address at 'email' property to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#email' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_ASC_002.py|


severity: Medium

title: Security Center shoud have security contact email configured to get notifications

description: Setting a valid email address in Security contact emails will enable Microsoft to contact you if the Microsoft Security Response Center (MSRC) discovers that your data has been accessed by an unlawful or unauthorized party. This will make sure that you are aware of any security issues and take prompt actions to mitigate the risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service: |['terraform']|


resourceTypes: ['azurerm_security_center_contact']


[file(securitycontacts.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/securitycontacts.rego
