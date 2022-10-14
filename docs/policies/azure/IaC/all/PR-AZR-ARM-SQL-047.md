



# Title: Ensure SQL servers don't have public network access enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-047

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_servers.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-047|
|eval|data.rule.sql_public_access|
|message|data.rule.sql_public_access_err|
|remediationDescription|In 'microsoft.sql/servers' resource, set 'publicNetworkAccess = Disabled' to fix the issue.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_SQL_047.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Always use Private Endpoint for Azure SQL Database and SQL Managed Instance  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers', 'microsoft.sql/servers/administrators']


[sql_servers.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego
