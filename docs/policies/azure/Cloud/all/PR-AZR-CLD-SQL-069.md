



# Title: Ensure Azure SQL Server has latest version of tls configured


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-069

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_400']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_servers.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-069|
|eval|data.rule.sql_server_latest_tls_configured|
|message|data.rule.sql_server_latest_tls_configured_err|
|remediationDescription|Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_CLD_SQL_069.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Databases']|



[sql_servers.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/sql_servers.rego
