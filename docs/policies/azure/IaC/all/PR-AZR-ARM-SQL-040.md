



# Title: Azure SQL Server threat detection alerts should be enabled for all threat types


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-040

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_alert_policy.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-040|
|eval|data.rule.sql_server_disabled_alerts|
|message|data.rule.sql_server_disabled_alerts_err|
|remediationDescription|For the source type 'microsoft.sql/servers/securityalertpolicies' make sure that properties.disabledAlerts does not exist or is empty.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/securityalertpolicies' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_SQL_040.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification._x005F<br>_x005F<br>This policy identifies Azure SQL servers that have disabled the detection of one or more threat types. To protect your SQL Servers, as a best practice, enable ADS detection for all types of threats.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers', 'microsoft.sql/managedinstances/securityalertpolicies', 'microsoft.sql/servers/securityalertpolicies']


[sql_alert_policy.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego
