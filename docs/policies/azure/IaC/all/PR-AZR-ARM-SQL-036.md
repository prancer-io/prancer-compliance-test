



# Title: Azure SQL Security Alert Policy should be configured to send alerts to the account administrators and configured email addresses


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-036

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_alert_policy.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-036|
|eval|data.rule.sql_server_email_addressess|
|message|data.rule.sql_server_email_addressess_err|
|remediationDescription|For Resource type 'microsoft.sql/servers/securityalertpolicies' make sure properties.emailAddresses exists and has a valid email address.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_SQL_036.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Provide the email address where alerts will be sent when anomalous activities are detected on SQL servers.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers', 'microsoft.sql/managedinstances/securityalertpolicies', 'microsoft.sql/servers/securityalertpolicies']


[sql_alert_policy.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego
