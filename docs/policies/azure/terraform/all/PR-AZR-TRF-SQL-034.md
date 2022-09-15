



# Master Test ID: PR-AZR-TRF-SQL-034


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_servers.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-034|
|eval|data.rule.sql_server_login|
|message|data.rule.sql_server_login_err|
|remediationDescription|In 'azurerm_sql_server' resource, make sure 'administrator_login' does not contains name like 'Admin/Administrator' to fix the issue. If 'administrator_login' property does not exist please add it. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server#administrator_login' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_034.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure SQL Server administrator login does not contains 'Admin/Administrator' as name

***<font color="white">Description:</font>*** You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_sql_server']


[sql_servers.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers.rego
