



# Title: SQL Managed Instance should have public endpoint access disabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-041

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_401']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_managedinstance.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-041|
|eval|data.rule.sql_mi_public_endpoint_disabled|
|message|data.rule.sql_mi_public_endpoint_disabled_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/azure-sql/managed-instance/public-endpoint-configure' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_SQL_041.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Always use Private Endpoint for Azure SQL Database and SQL Managed Instance  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|[]|
|service|['Databases']|



[sql_managedinstance.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/sql_managedinstance.rego
