



# Title: Send email notification should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-ASC-003

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([securitycontacts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-ASC-003|
|eval|data.rule.alert_notifications|
|message|data.rule.alert_notifications_err|
|remediationDescription|For Resource type 'microsoft.security/securitycontacts' make sure alertNotifications exists and the value is set to 'On'.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_ASC_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Setting the security alert Send email notification for alerts to On ensures that emails are sent from Microsoft if their security team determines a potential security breach has taken place.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.security/securitycontacts']


[securitycontacts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/securitycontacts.rego
