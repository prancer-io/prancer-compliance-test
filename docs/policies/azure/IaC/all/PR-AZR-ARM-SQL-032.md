



# Title: Ensure Security Alert is enabled on Azure SQL Managed Instance


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-032

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_alert_policy.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-032|
|eval|data.rule.sql_managed_instance_alert|
|message|data.rule.sql_managed_instance_alert_err|
|remediationDescription|In Resource of type "Microsoft.sql/managedinstances/securityalertpolicies" make sure properties.state exists and value is set to "Enabled" .<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances/securityalertpolicies' target='_blank'>here</a>|
|remediationFunction|PR_AZR_ARM_SQL_032.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Advanced data security should be enabled on your SQL managed instance.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers', 'microsoft.sql/managedinstances/securityalertpolicies', 'microsoft.sql/servers/securityalertpolicies']


[sql_alert_policy.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego
