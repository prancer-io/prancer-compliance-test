



# Title: Security Center should have security contact emails configured to get notifications


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-ASC-002

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([securitycontacts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-ASC-002|
|eval|data.rule.securitycontacts|
|message|data.rule.securitycontacts_err|
|remediationDescription|Make sure you are following the ARM template guidelines for security center by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts' target='_blank'>here</a>|
|remediationFunction|PR_AZR_ARM_ASC_002.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Setting a valid email address in Security contact emails will enable Microsoft to contact you if the Microsoft Security Response Center (MSRC) discovers that your data has been accessed by an unlawful or unauthorized party. This will make sure that you are aware of any security issues and take prompt actions to mitigate the risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.security/securitycontacts']


[securitycontacts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/securitycontacts.rego
