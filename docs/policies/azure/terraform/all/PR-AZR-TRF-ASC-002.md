



# Master Test ID: PR-AZR-TRF-ASC-002


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([securitycontacts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-ASC-002|
|eval|data.rule.securitycontacts|
|message|data.rule.securitycontacts_err|
|remediationDescription|In 'azurerm_security_center_contact' resource, set a valid email address at 'email' property to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#email' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_ASC_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Security Center shoud have security contact email configured to get notifications

***<font color="white">Description:</font>*** Setting a valid email address in Security contact emails will enable Microsoft to contact you if the Microsoft Security Response Center (MSRC) discovers that your data has been accessed by an unlawful or unauthorized party. This will make sure that you are aware of any security issues and take prompt actions to mitigate the risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_security_center_contact']


[securitycontacts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/securitycontacts.rego
