



# Title: Ensure SQL servers don't have public network access enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-047

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_400']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_servers.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-047|
|eval|data.rule.sql_public_access|
|message|data.rule.sql_public_access_err|
|remediationDescription|Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_CLD_SQL_047.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Always use Private Endpoint for Azure SQL Database and SQL Managed Instance  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Databases']|



[sql_servers.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/sql_servers.rego
