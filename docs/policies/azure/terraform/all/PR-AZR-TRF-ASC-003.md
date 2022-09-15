



# Master Test ID: PR-AZR-TRF-ASC-003


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([securitycontacts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-ASC-003|
|eval|data.rule.securitycontacts_alert_notifications_enabled|
|message|data.rule.securitycontacts_alert_notifications_enabled_err|
|remediationDescription|In 'azurerm_security_center_contact' resource, set 'alert_notifications = true' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#alert_notifications' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_ASC_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Security Center shoud send security alerts notifications to the security contact

***<font color="white">Description:</font>*** This policy will identify security centers which dont have configuration enabled to send security alerts notifications to the security contact and alert if missing.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_security_center_contact']


[securitycontacts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/securitycontacts.rego
