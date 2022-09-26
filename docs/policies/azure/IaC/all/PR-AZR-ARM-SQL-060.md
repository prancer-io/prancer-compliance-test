



# Title: Ensure MySQL servers don't have public network access enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-060

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbforMySQL.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-060|
|eval|data.rule.mysql_public_access_disabled|
|message|data.rule.mysql_public_access_disabled_err|
|remediationDescription|In 'microsoft.dbformysql/servers' resource, set 'publicNetworkAccess = Disabled' to fix the issue.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformysql/servers' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_SQL_060.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Always use Private Endpoint for Azure MySQL Database Server  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.dbformysql/servers']


[dbforMySQL.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/dbforMySQL.rego
