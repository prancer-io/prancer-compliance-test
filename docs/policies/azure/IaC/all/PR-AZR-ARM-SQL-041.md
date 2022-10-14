



# Title: SQL Managed Instance should have public endpoint access disabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-041

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_managedinstance.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-041|
|eval|data.rule.sql_mi_public_endpoint_disabled|
|message|data.rule.sql_mi_public_endpoint_disabled_err|
|remediationDescription|IN ARM template make sure 'properties.publicDataEndpointEnabled' does not exist or if exist set value 'false' to 'properties.publicDataEndpointEnabled' under resource of type 'microsoft.sql/managedinstances'. Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_SQL_041.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Always use Private Endpoint for Azure SQL Database and SQL Managed Instance  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/managedinstances']


[sql_managedinstance.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_managedinstance.rego
