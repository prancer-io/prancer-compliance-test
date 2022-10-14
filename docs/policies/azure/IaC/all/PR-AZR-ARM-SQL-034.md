



# Title: Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-034

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_alert_policy.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-034|
|eval|data.rule.sql_server_email_account|
|message|data.rule.sql_server_email_account_err|
|remediationDescription|For Resource type 'microsoft.sql/servers/securityalertpolicies' make sure properties.emailAccountAdmins exists and the value is set to true.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_SQL_034.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** VA scan reports and alerts will be sent to admins and subscription owners by enabling the setting 'Also send email notifications to admins and subscription owners'. This may help in reducing the time required for identifying risks and taking corrective measures.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers', 'microsoft.sql/managedinstances/securityalertpolicies', 'microsoft.sql/servers/securityalertpolicies']


[sql_alert_policy.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego
