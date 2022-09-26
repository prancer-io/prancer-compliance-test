



# Title: Auditing for SQL database should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-005

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbauditingsettings.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-005|
|eval|data.rule.sql_logical_db_log_audit|
|message|data.rule.sql_logical_db_log_audit_err|
|remediationDescription|Make sure you are following the ARM template guidelines for SQL Server by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/auditingsettings' target='_blank'>here</a>. Make sure the state of auditing is enabled|
|remediationFunction|PR_AZR_ARM_SQL_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Database events are tracked by the Auditing feature and the events are written to an audit log in your Azure storage account. This process helps you to monitor database activity, and get insight into anomalies that could indicate business concerns or suspected security violations.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers/databases', 'microsoft.sql/servers/databases/auditingsettings']


[dbauditingsettings.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/dbauditingsettings.rego
