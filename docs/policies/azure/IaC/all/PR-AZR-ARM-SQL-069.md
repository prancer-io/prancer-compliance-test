



# Title: Ensure Azure SQL Server has latest version of tls configured


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-069

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_servers.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-069|
|eval|data.rule.sql_server_latest_tls_configured|
|message|data.rule.sql_server_latest_tls_configured_err|
|remediationDescription|In 'microsoft.sql/servers' resource, set 'minimalTlsVersion = 1.2' to fix the issue.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_SQL_069.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers', 'microsoft.sql/servers/administrators']


[sql_servers.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego
