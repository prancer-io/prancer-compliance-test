



# Title: Ensure SQL Server Threat Detection is Enabled and Retention Logs are equal or greater than 90 days


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-038

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_alert_policy.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-038|
|eval|data.rule.sql_server_retention_days|
|message|data.rule.sql_server_retention_days_err|
|remediationDescription|For Resource type 'microsoft.sql/servers/securityalertpolicies' make sure properties.retentionDays exists and the value is set to equal or greater than 90.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_SQL_038.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Azure SQL Database Threat Detection is a security intelligence feature built into the Azure SQL Database service. Working around the clock to learn, profile and detect anomalous database activities, Azure SQL Database Threat Detection identifies potential threats to the database. Security officers or other designated administrators can get an immediate notification about suspicious database activities as they occur. Each notification provides details of the suspicious activity and recommends how to further investigate and mitigate the threat.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers', 'microsoft.sql/managedinstances/securityalertpolicies', 'microsoft.sql/servers/securityalertpolicies']


[sql_alert_policy.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego
