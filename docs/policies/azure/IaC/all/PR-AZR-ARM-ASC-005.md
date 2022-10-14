



# Title: Security Center should send security alerts notifications to subscription admins


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-ASC-005

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([securitycontacts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-ASC-005|
|eval|data.rule.securitycontacts_alerts_to_admins_enabled|
|message|data.rule.securitycontacts_alerts_to_admins_enabled_err|
|remediationDescription|In 'microsoft.security/securitycontacts' resource, set 'alertsToAdmins = On' to fix the issue.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_ASC_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy will identify security centers which dont have configuration enabled to send security alerts notifications to subscription admins and alert if missing.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.security/securitycontacts']


[securitycontacts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/securitycontacts.rego
