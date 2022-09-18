



# Title: Ensure PostgreSQL servers don't have public network access enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-066

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([postgreSQL.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-066|
|eval|data.rule.postgresql_public_access_disabled|
|message|data.rule.postgresql_public_access_disabled_err|
|remediationDescription|In 'microsoft.dbforpostgresql/servers' resource, set 'publicNetworkAccess = disabled' to fix the issue.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_SQL_066.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Always use Private Endpoint for PostgreSQL Server  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.dbforpostgresql/servers']


[postgreSQL.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego
