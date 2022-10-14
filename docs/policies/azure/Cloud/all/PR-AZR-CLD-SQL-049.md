



# Title: Ensure SQL Server administrator login does not contain 'Admin/Administrator' as name


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-049

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_400']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_servers.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-049|
|eval|data.rule.sql_logical_server_login|
|message|data.rule.sql_logical_server_login_err|
|remediationDescription|In Azure Portal<br>1. Go to SQL Servers<br>2. For each SQL Server<br>3. Select Active Directory admin<br>4. Press the Set Admin at the top of the page<br>5. Select the active directory user you want to set as AD Admin for the SQL server.<br>6. Press the Remove admin if not needed.<br><br>Default Value: By default no AD Administrator is set for SQL server<br><br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/administrators' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_CLD_SQL_049.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice']|
|service|['Databases']|



[sql_servers.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/sql_servers.rego
