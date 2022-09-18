



# Title: Ensure SQL Server administrator login does not contain 'Admin/Administrator' as name


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-049

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_servers.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-049|
|eval|data.rule.sql_logical_server_login|
|message|data.rule.sql_logical_server_login_err|
|remediationDescription|In Resource of type "Microsoft.Sql/servers/administrators" make sure properties.login exists and the value isn't set to 'admin' or 'administrator'.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/administrators' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_SQL_049.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers', 'microsoft.sql/servers/administrators']


[sql_servers.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego
