



# Title: Azure SQL server audit log retention should be 90 days or higher


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-044

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_servers_auditing.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-044|
|eval|data.rule.sql_server_audit_log_retention|
|message|data.rule.sql_server_audit_log_retention_err|
|remediationDescription|For Resource type 'microsoft.sql/servers/auditingsettings' make sure retentionDays exists and equal or greater than 90 days.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2021-02-01-preview/servers/auditingsettings' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_SQL_044.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access. We recommend you configure SQL server audit retention to be 90 days or higher.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers', 'microsoft.sql/servers/auditingsettings']


[sql_servers_auditing.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers_auditing.rego
