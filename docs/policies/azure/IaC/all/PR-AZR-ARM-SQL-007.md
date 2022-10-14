



# Title: Azure SQL Database Auditing Retention should be 90 days or more


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-007

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbauditingsettings.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-007|
|eval|data.rule.sql_logical_db_log_retention|
|message|data.rule.sql_logical_db_log_retention_err|
|remediationDescription|Make sure you are following the ARM template guidelines for SQL Server by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/auditingsettings' target='_blank'>here</a>. Make sure retentionDays is at least 90|
|remediationFunction|PR_AZR_ARM_SQL_007.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies SQL Databases that have Auditing Retention of fewer than 90 days. Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access. It is recommended to configure SQL database Audit Retention to be greater than or equal to 90 days.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers/databases', 'microsoft.sql/servers/databases/auditingsettings']


[dbauditingsettings.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/dbauditingsettings.rego
